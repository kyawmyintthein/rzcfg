package rzcfg

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/kyawmyintthein/rzcfg/protopb/service"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodbstreams"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
	"github.com/kyawmyintthein/rzlog"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

type (
	Event struct {
		EventType string `json:"event_type"`
		Timestamp int64  `json:"timestamp"`
	}

	Callback func(context.Context, Event, interface{})

	SecretsManagerCfg struct {
		SecretID     string `mapstructure:"secret_id" json:"secret_id" envconfig:"SECRET_ID"`
		VersionStage string `mapstructure:"version_stage" json:"version_stage" envconfig:"VERSION_STAGE" default:"AWSCURRENT"`
	}

	mode      = string
	ServerCfg struct {
		ServerAddress                 string            `mapstructure:"config_server_address" json:"config_server_address" envconfig:"CONFIG_SERVER_ADDRESS" required:"true" default:"localhost:7000"`
		AppName                       string            `mapstructure:"app_name" json:"app_name" envconfig:"APP_NAME" required:"true" default:""`
		Env                           string            `mapstructure:"env" json:"env" envconfig:"ENV" required:"true" default:"dev"`
		SecretsManager                SecretsManagerCfg `mapstructure:"secrets_manager" json:"secrets_manager" envconfig:"SECRETS_MANAGER"`
		IsSecure                      bool              `mapstructure:"is_secure" json:"is_secure" envconfig:"IS_SECURE" default:"true"`
		EnableAutoReconnect           bool              `mapstructure:"enable_auto_reconnect" json:"enable_auto_reconnect" envconfig:"ENABLE_AUTO_RECONNECT" default:"true"`
		DialTimeoutInMillisecond      int64             `mapstructure:"dial_timeout_in_millisecond" json:"dial_timeout_in_millisecond" envconfig:"DIAL_TIMEOUT_IN_MILLISECOND" default:"3000"`
		ReconnectBackoffInMillisecond int64             `mapstructure:"reconnect_backoff_in_millisecond" json:"reconnect_backoff_in_millisecond" envconfig:"RECONNECT_BACKOFF_IN_MILLISECOND" default:"3000"`
		RequestTimeoutInMillisecond   int64             `mapstructure:"request_timeout_in_millisecond" json:"request_timeout_in_millisecond" envconfig:"REQUEST_TIMEOUT_IN_MILLISECOND" default:"5000"`
	}

	DynamodbDBCfg struct {
		Table                       string            `json:"config_dynamodb_table" envconfig:"CONFIG_DYNAMODB_TABLE" required:"true"`
		AppName                     string            `json:"app_name" envconfig:"APP_NAME" required:"true" default:""`
		Env                         string            `json:"env" envconfig:"ENV" required:"true" default:"dev"`
		Version                     int64             `json:"version" envconfig:"VERSION" required:"true"`
		SecretsManager              SecretsManagerCfg `json:"secrets_manager" envconfig:"SECRETS_MANAGER"`
		RequestTimeoutInMillisecond int64             `mapstructure:"request_timeout_in_millisecond" json:"request_timeout_in_millisecond" envconfig:"REQUEST_TIMEOUT_IN_MILLISECOND" default:"5000"`
	}

	Client interface {
		Init(context.Context, interface{}) error
		Register(string, Callback)
	}

	client struct {
		mode                mode
		mux                 sync.Mutex
		serverCfg           *ServerCfg
		dynamodbDBCfg       *DynamodbDBCfg
		conn                *grpc.ClientConn
		viper               *viper.Viper
		v                   interface{}
		clientDetail        *service.ClientDetail
		notificationClient  service.NotificationServiceClient
		configurationClient service.ConfigurationServiceClient
		callbacks           map[string]Callback
		logger              rzlog.Logger
		signal              chan error

		enableSecretsManager bool
		secretsManager       *secretsmanager.SecretsManager
		dynamodb             *dynamodb.DynamoDB
		dynamodbStream       *dynamodbstreams.DynamoDBStreams
		table                string
	}

	configuration struct {
		AppEnv     string                 `json:"app_env"`
		Version    int64                  `json:"version"`
		Attributes map[string]interface{} `json:"attributes"`
	}
)

const (
	UUIDEvent                string = "UUID_EVENT"
	UpdateConfigurationEvent string = "UPDATE_CONFIGURATION_EVENT"
	mode_Server                     = "Server"
	mode_Dynamodb                   = "Dynamodb"
)

var _defaultLogCfg = rzlog.LogCfg{
	FilePath: "",
	Level:    "info",
	Format:   "json",
}

func LoadConfig(configFilePath string, prefix string, v interface{}) error {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		return fmt.Errorf("invalid struct type: only support pointer type")
	}

	godotenv.Load(configFilePath)
	err := envconfig.Process(strings.ToUpper(prefix), v)
	if err != nil {
		return err
	}

	return nil
}

func NewConfigServerClient(cfg *ServerCfg, opts ...Option) (Client, error) {
	options := NewOptions(opts...)

	logger, ok := options.Context.Value(loggerKey{}).(rzlog.Logger)
	if !ok {
		logger = rzlog.New(_defaultLogCfg)
	}

	ip, _ := getIPAddress()
	cli := &client{
		mode:      mode_Server,
		mux:       sync.Mutex{},
		serverCfg: cfg,
		clientDetail: &service.ClientDetail{
			AppName: cfg.AppName,
			Env:     cfg.Env,
			Address: ip,
		},
		callbacks: make(map[string]Callback),
		logger:    logger,
		signal:    make(chan error),
	}

	secretsManager, ok := options.Context.Value(secretsManagerKey{}).(*secretsmanager.SecretsManager)
	if ok {
		cli.secretsManager = secretsManager
		cli.enableSecretsManager = true
	}

	cli.viper = viper.New()
	cli.viper.SetConfigType("json")

	err := cli.connectToServer()
	if err != nil {
		return nil, err
	}

	return cli, nil
}

func getIPAddress() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

func (cli *client) connectToServer() error {
	ctx, _ := context.WithTimeout(context.Background(), time.Duration(cli.serverCfg.DialTimeoutInMillisecond)*time.Millisecond)
	h := sha1.New()
	io.WriteString(h, fmt.Sprintf("%s-%s", cli.serverCfg.AppName, cli.serverCfg.Env))
	clientHex := fmt.Sprintf("%x", h.Sum(nil))
	ctxWithHex := context.WithValue(ctx, "clientHex", clientHex)

	var (
		conn *grpc.ClientConn
		err  error
	)

	var kasp = keepalive.ClientParameters{
		PermitWithoutStream: true,
	}
	if cli.serverCfg.IsSecure {
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: false,
		})
		conn, err = grpc.DialContext(ctxWithHex, cli.serverCfg.ServerAddress, grpc.WithTransportCredentials(creds), grpc.WithKeepaliveParams(kasp), grpc.WithBlock())
	} else {
		conn, err = grpc.DialContext(ctxWithHex, cli.serverCfg.ServerAddress, grpc.WithInsecure(), grpc.WithBlock(), grpc.WithKeepaliveParams(kasp))
	}

	if err != nil {
		cli.logger.Error(ctx, err, "failed to connect config server")
		return err
	}

	cli.conn = conn
	cli.notificationClient = service.NewNotificationServiceClient(cli.conn)
	cli.configurationClient = service.NewConfigurationServiceClient(cli.conn)
	return nil
}

func NewConfigDBClient(cfg *DynamodbDBCfg, sess *session.Session, opts ...Option) (Client, error) {
	options := NewOptions(opts...)

	logger, ok := options.Context.Value(loggerKey{}).(rzlog.Logger)
	if !ok {
		logger = rzlog.New(_defaultLogCfg)
	}

	ip, _ := getIPAddress()
	cli := &client{
		mode:          mode_Dynamodb,
		mux:           sync.Mutex{},
		dynamodbDBCfg: cfg,
		clientDetail: &service.ClientDetail{
			AppName: cfg.AppName,
			Env:     cfg.Env,
			Version: cfg.Version,
			Address: ip,
		},
		callbacks:      make(map[string]Callback),
		logger:         logger,
		signal:         make(chan error),
		dynamodb:       dynamodb.New(sess),
		dynamodbStream: dynamodbstreams.New(sess),
		table:          cfg.Table,
	}

	secretsManager, ok := options.Context.Value(secretsManagerKey{}).(*secretsmanager.SecretsManager)
	if ok {
		cli.secretsManager = secretsManager
		cli.enableSecretsManager = true
	}

	cli.viper = viper.New()
	cli.viper.SetConfigType("json")

	return cli, nil
}

func (cli *client) Init(ctx context.Context, v interface{}) error {
	if reflect.ValueOf(v).Kind() != reflect.Ptr {
		return fmt.Errorf("invalid struct type: only support pointer type")
	}
	cli.v = v
	switch cli.mode {
	case mode_Server:
		err := cli.retrieveConfigurationDataFromServer(ctx)
		if err != nil {
			return err
		}
	case mode_Dynamodb:
		err := cli.retrieveConfigurationDataFromDB(ctx)
		if err != nil {
			return err
		}
	}

	rzlog.InfoKV(ctx, rzlog.KV{"config": cli.v}, "loaded config object")
	return nil
}

func (cli *client) retrieveConfigurationDataFromServer(ctx context.Context) error {
	ctxWithTimeout, _ := context.WithTimeout(ctx, time.Duration(cli.serverCfg.RequestTimeoutInMillisecond)*time.Millisecond)
	resp, err := cli.configurationClient.GetConfiguration(ctxWithTimeout, &service.GetConfigurationRequest{
		AppName: cli.clientDetail.AppName,
		Env:     cli.clientDetail.Env,
	})
	if err != nil {
		cli.logger.Error(ctx, err, "failed to retrieve configuration")
		return err
	}
	if resp.Error != nil {
		return NewGeneralConfigServerError(resp.Error.Code, resp.Error.Message)
	}

	data := resp.Configuration.Attributes
	rzlog.InfoKV(ctx, rzlog.KV{"config": string(data)}, "client.get_configuration")
	err = cli.viper.ReadConfig(bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	err = cli.viper.Unmarshal(cli.v)
	if err != nil {
		return err
	}

	cli.clientDetail.Version = resp.Configuration.Version
	err = cli.registerClient(ctx)
	if err != nil {
		return err
	}

	rzlog.InfoKV(ctx, rzlog.KV{"config": cli.v}, "config_object")
	err = cli.getSecrets(ctx, cli.serverCfg.SecretsManager.SecretID, cli.serverCfg.SecretsManager.VersionStage)
	if err != nil {
		return err
	}

	ctxWithClientID := context.WithValue(ctx, "clientID", cli.clientDetail.Uuid)
	go cli.sync(ctxWithClientID)
	if cli.serverCfg.EnableAutoReconnect {
		go cli.reconnect(ctxWithClientID)
	}

	return nil
}

func (cli *client) retrieveConfigurationDataFromDB(ctx context.Context) error {
	ctxWithTimeout, _ := context.WithTimeout(ctx, time.Duration(cli.dynamodbDBCfg.RequestTimeoutInMillisecond)*time.Millisecond)
	pk := fmt.Sprintf("%s_%s", cli.dynamodbDBCfg.AppName, cli.dynamodbDBCfg.Env)
	resp, err := cli.dynamodb.GetItemWithContext(ctxWithTimeout, &dynamodb.GetItemInput{
		Key: map[string]*dynamodb.AttributeValue{
			"app_env": {
				S: aws.String(pk),
			},
			"version": {
				N: aws.String(fmt.Sprintf("%d", cli.dynamodbDBCfg.Version)),
			},
		},
		TableName: &cli.table,
	})
	if err != nil {
		cli.logger.Error(ctx, err, "failed to retrieve configuration")
		return err
	}

	if resp.Item == nil {
		err = fmt.Errorf("configuration not found")
		cli.logger.Error(ctx, err, "failed to retrieve configuration")
		return err
	}

	var config configuration
	err = dynamodbattribute.UnmarshalMap(resp.Item, &config)
	if err != nil {
		return err
	}

	data, err := json.Marshal(config.Attributes)
	if err != nil {
		return err
	}

	rzlog.InfoKV(ctx, rzlog.KV{"config data": string(data)}, "client.get_configuration")
	err = cli.viper.ReadConfig(bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	err = cli.viper.Unmarshal(cli.v)
	if err != nil {
		return err
	}

	rzlog.InfoKV(ctx, rzlog.KV{"config": cli.v}, "config object before secrets manager")
	err = cli.getSecrets(ctx, cli.dynamodbDBCfg.SecretsManager.SecretID, cli.dynamodbDBCfg.SecretsManager.VersionStage)
	if err != nil {
		return err
	}

	return nil
}

func (cli *client) getSecrets(ctx context.Context, secretID string, versionStage string) error {
	if !cli.enableSecretsManager {
		return nil
	}
	result, err := cli.secretsManager.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretID),
		VersionStage: aws.String(versionStage),
	})
	if err != nil {
		return err
	}

	err = cli.viper.MergeConfig(bytes.NewBuffer([]byte(*result.SecretString)))
	if err != nil {
		return err
	}

	err = cli.viper.Unmarshal(&cli.v)
	if err != nil {
		return err
	}
	return nil
}

func (cli *client) registerClient(ctx context.Context) error {
	clientDetailWithUUID, err := cli.notificationClient.Register(ctx, cli.clientDetail)
	if err != nil {
		return err
	}

	if clientDetailWithUUID.Uuid == "" {
		return fmt.Errorf("failed to get client UUID")
	}
	cli.clientDetail = clientDetailWithUUID
	cli.logger.DebugKV(ctx, rzlog.KV{"configuration": cli.v, "version": cli.clientDetail.Version, "client_id": clientDetailWithUUID}, "registered to server")
	return nil
}

func (cli *client) sync(ctx context.Context) {
	stream, err := cli.notificationClient.Notify(ctx)
	if err != nil {
		cli.signal <- err
		return
	}

	err = stream.Send(cli.clientDetail)
	if err != nil {
		cli.signal <- err
		return
	}

	for {
		// listen for streams
		notificationEvent, err := stream.Recv()
		if err != nil { // some error occured
			if err == io.EOF { //no more stream to listen
				cli.logger.ErrorKV(ctx, err, rzlog.KV{"client_id": cli.clientDetail.Uuid}, "stream.Recv EOF erorr")
			} else {
				cli.logger.DebugKV(ctx, rzlog.KV{"client_id": cli.clientDetail.Uuid, "error": err}, "stream.Recv error")
			}
			cli.signal <- err
			break
		}

		if notificationEvent.Error != nil {
			err = NewGeneralConfigServerError(notificationEvent.Error.Code, notificationEvent.Error.Message)
			cli.logger.Errorf(ctx, err, "server error")
			cli.signal <- err
			break
		}

		cli.logger.InfoKV(stream.Context(), rzlog.KV{"event": notificationEvent.Event}, "new event is received")
		switch notificationEvent.Event.EventType {
		case UpdateConfigurationEvent:
			err = cli.onUpdateEvent(stream.Context(), notificationEvent)
			if err != nil {
				cli.logger.Errorf(ctx, err, "onUpdateEvent")
				cli.signal <- err
				break
			} else {
				err = stream.Send(cli.clientDetail)
				if err != nil {
					cli.logger.Errorf(ctx, err, "stream.Send")
					cli.signal <- err
					break
				}
			}
		}
	}
}

func (cli *client) reconnect(ctx context.Context) {
	go func() {
		for {
			err := <-cli.signal
			cli.logger.DebugKV(ctx, rzlog.KV{"error": err}, "error signal received")
			go func() {
				for {
					time.Sleep(time.Duration(cli.serverCfg.ReconnectBackoffInMillisecond) * time.Millisecond)
					err = cli.registerClient(ctx)
					if err != nil {
						cli.logger.DebugKV(ctx, rzlog.KV{"client_id": cli.clientDetail.Uuid, "error": err}, "failed to reigster server")
						continue
					}

					go cli.sync(ctx)
					cli.logger.DebugKV(ctx, rzlog.KV{"client_id": cli.clientDetail.Uuid, "error": err}, "reconnected stream to server")
					break
				}
			}()
		}
	}()
}

func (cli *client) onUpdateEvent(ctx context.Context, notificationEvent *service.NotificationEvent) error {
	watchedKeys := make(map[string]interface{})
	resp, err := cli.configurationClient.GetConfiguration(ctx, &service.GetConfigurationRequest{
		AppName: cli.serverCfg.AppName,
		Env:     cli.serverCfg.Env,
	})
	if err != nil {
		return err
	}

	if resp.Error != nil {
		return NewGeneralConfigServerError(resp.Error.Code, resp.Error.Message)
	}

	for kid, _ := range cli.callbacks {
		watchedKeys[kid] = cli.viper.Get(kid)
	}

	data := resp.Configuration.Attributes
	err = cli.viper.ReadConfig(bytes.NewBuffer(data))
	if err != nil {
		return err
	}

	err = cli.viper.Unmarshal(cli.v)
	if err != nil {
		return err
	}

	err = cli.getSecrets(ctx, cli.serverCfg.SecretsManager.SecretID, cli.serverCfg.SecretsManager.VersionStage)
	if err != nil {
		return err
	}

	cli.clientDetail.Version = resp.Configuration.Version
	cli.logger.DebugKV(ctx, rzlog.KV{"configuration": string(data), "version": resp.Configuration.Version}, "Updated configuration")

	cli.executeCallbacks(ctx, watchedKeys, Event{
		EventType: notificationEvent.Event.EventType,
		Timestamp: notificationEvent.Event.Timestamp,
	})
	return nil
}

func (cli *client) Register(fid string, fn Callback) {
	cli.mux.Lock()
	defer cli.mux.Unlock()
	cli.callbacks[fid] = fn
}

func (cli *client) executeCallbacks(ctx context.Context, watchedKeys map[string]interface{}, event Event) {
	for kid, callback := range cli.callbacks {
		oldVal, ok := watchedKeys[kid]
		if ok {
			callback(ctx, event, oldVal)
		}
	}
}
