generate:
	/usr/bin/buf-Linux-x86_64 generate --path ./protofiles/domain
	/usr/bin/buf-Linux-x86_64 generate --path ./protofiles/service

install:
	go get \
		google.golang.org/protobuf/cmd/protoc-gen-go \
		google.golang.org/grpc/cmd/protoc-gen-go-grpc \
		github.com/bufbuild/buf/cmd/buf