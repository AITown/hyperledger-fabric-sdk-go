package peerex

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

//ClientConn rpc 连接
func (node *NodeEnv) ClientConn() error {
	conn, err := node.grpcConnection()
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("endorser client failed to connect to %s", node.Address))
	}
	node.Connect = conn
	return nil
}

//简化版的连接
func (node *NodeEnv) grpcConnection() (*grpc.ClientConn, error) {
	logger.Debug("创建grpc 连接")
	var dialOpts []grpc.DialOption

	tls, err := credentials.NewClientTLSFromFile(node.RootCertFile, node.HostnameOverride)
	if err != nil {
		return nil, err
	}
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(tls), grpc.WithBlock())

	ctx, cancel := context.WithTimeout(context.Background(), node.ConnTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, node.Address, dialOpts...)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create new connection")
	}
	return conn, nil
}
