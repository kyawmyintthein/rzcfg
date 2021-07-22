package rzcfg

import (
	"context"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/kyawmyintthein/rzlog"
)

// Options struct to keep all parameters in context.Context
type Options struct {
	Context context.Context
}

// Option optional parameter as function
type Option func(o *Options)

// NewOptions convert all Option function to Options struct
func NewOptions(opts ...Option) Options {
	options := Options{
		Context: context.Background(),
	}

	for _, o := range opts {
		o(&options)
	}

	return options
}

type loggerKey struct{}

func WithLogger(log rzlog.Logger) Option {
	return func(o *Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		o.Context = context.WithValue(o.Context, loggerKey{}, log)
	}
}

type secretsManagerKey struct{}

func WithSecretsManager(secretsManager *secretsmanager.SecretsManager) Option {
	return func(o *Options) {
		if o.Context == nil {
			o.Context = context.Background()
		}
		o.Context = context.WithValue(o.Context, secretsManagerKey{}, secretsManager)
	}
}
