package peerex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"hyperledger-fabric-sdk-go/utils"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

var (
	// Max send and receive bytes for grpc clients and servers
	MaxRecvMsgSize = 100 * 1024 * 1024
	MaxSendMsgSize = 100 * 1024 * 1024
	// Default peer keepalive options
	ClientInterval = time.Duration(1) * time.Minute  // 1 min
	ClientTimeout  = time.Duration(20) * time.Second // 20 sec - gRPC default
)
var conut = 1

func (node *NodeEnv) ClientConn() error {
	conn, err := node.grpcConnection()
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("endorser client failed to connect to %s", node.Address))
	}
	node.Connect = conn
	return nil
}

func (node *NodeEnv) grpcConnection() (*grpc.ClientConn, error) {
	client := &GRPCClient{}
	var dialOpts []grpc.DialOption

	// parse NodeConfig
	err := client.parseNodeConfig(node)
	if err != nil {
		return nil, err
	}

	dialOpts = append(dialOpts, client.dialOpts...)

	// set transport credentials and max send/recv message sizes
	// immediately before creating a connection in order to allow
	// SetServerRootCAs / SetMaxRecvMsgSize / SetMaxSendMsgSize
	//  to take effect on a per connection basis

	// tls, err := credentials.NewClientTLSFromFile(node.RootCertFile, node.HostnameOverride)
	// if err != nil {
	// 	return nil, err
	// }
	client.tlsConfig.ServerName = node.HostnameOverride
	dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(client.tlsConfig)))

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(client.maxRecvMsgSize),
		grpc.MaxCallSendMsgSize(client.maxSendMsgSize),
	))

	ctx, cancel := context.WithTimeout(context.Background(), node.ConnTimeout)
	defer cancel()
	conn, err := grpc.DialContext(ctx, node.Address, dialOpts...)
	if err != nil {
		return nil, errors.WithMessage(errors.WithStack(err), "failed to create new connection")
	}
	return conn, nil
}

func (client *GRPCClient) parseNodeConfig(node *NodeEnv) error {
	if node == nil || !node.TLS {
		return nil
	}
	client.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12} // TLS 1.2 only

	caPEM, err := utils.ReadCert(node.RootCertFile)
	if err != nil {
		return errors.New("can not load  node.RootCertFile")
	}
	serverRootCAs := [][]byte{caPEM}

	if len(serverRootCAs) > 0 {
		client.tlsConfig.RootCAs = x509.NewCertPool()
		for _, certBytes := range serverRootCAs {
			if ok := client.tlsConfig.RootCAs.AppendCertsFromPEM(certBytes); !ok {
				logger.Debugf("error adding root certificate")
				return errors.New("error adding root certificate")
			}
		}
	}

	cert, err := node.GetCertificate()
	if err != nil {
		return err
	}
	client.tlsConfig.Certificates = append(client.tlsConfig.Certificates, cert)

	// keepalive options use defaults
	kap := keepalive.ClientParameters{
		Time:    ClientInterval,
		Timeout: ClientTimeout,
	}

	kap.PermitWithoutStream = true
	// set keepalive and blocking  grpc.WithBlock() 阻塞直到连接成功   没有WithBlock() 直接返回连接，会在后台连接
	client.dialOpts = append(client.dialOpts, grpc.WithKeepaliveParams(kap), grpc.WithBlock())
	client.timeout = node.ConnTimeout
	// set send/recv message size to package defaults
	client.maxRecvMsgSize = MaxRecvMsgSize
	client.maxSendMsgSize = MaxSendMsgSize
	return nil
}

func (node *NodeEnv) GetCertificate() (tls.Certificate, error) {
	var (
		cert tls.Certificate
		err  error
	)

	if node.TLSClient {
		// make sure we have both Key and Certificate
		key, err := utils.ReadCert(node.KeyFile)
		if err != nil {
			err = errors.New("can not read node.KeyFile")
		}
		certificate, err := utils.ReadCert(node.CertFile)
		if err != nil {
			err = errors.New("can not read node.CertFile")
		}
		cert, err = tls.X509KeyPair(certificate, key)
		if err != nil {
			err = errors.WithMessage(err, "failed to load client certificate")
		}
	}

	return cert, err
}

// //最简化版的连接
// func grpcConnection(node *NodeEnv) (*grpc.ClientConn, error) {

// 	var dialOpts []grpc.DialOption
// 	// dialOpts = append(dialOpts, client.dialOpts...)

// 	// set transport credentials and max send/recv message sizes
// 	// immediately before creating a connection in order to allow
// 	// SetServerRootCAs / SetMaxRecvMsgSize / SetMaxSendMsgSize
// 	//  to take effect on a per connection basis
// 	fmt.Println("get root ca path", node.RootCertFile)
// 	tls, err := credentials.NewClientTLSFromFile(node.RootCertFile, node.HostnameOverride)
// 	if err != nil {
// 		return nil, err
// 	}
// 	dialOpts = append(dialOpts, grpc.WithTransportCredentials(tls))

// 	// dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(
// 	// 	grpc.MaxCallRecvMsgSize(client.maxRecvMsgSize),
// 	// 	grpc.MaxCallSendMsgSize(client.maxSendMsgSize),
// 	// ))

// 	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
// 	defer cancel()
// 	conn, err := grpc.DialContext(ctx, node.Address, dialOpts...)
// 	if err != nil {
// 		return nil, errors.WithMessage(errors.WithStack(err), "failed to create new connection")
// 	}
// 	return conn, nil
// }
