package peerex

import (
	"context"
	"fmt"
	"hyperledger-fabric-sdk-go/utils"
	"io/ioutil"

	"github.com/hyperledger/fabric/core/comm"
	ab "github.com/hyperledger/fabric/protos/orderer"
	"github.com/pkg/errors"
)

// OrdererClient represents a client for communicating with an ordering
// service
type OrdererClient struct {
	commonClient
}

func (order *OrderEnv) NewordererClientForAddress() (*OrdererClient, error) {
	// _, _, clientConfig, err := configFromEnv("orderer")
	clientConfig, err := order.GetConfig()
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config for OrdererClient")
	}
	return order.newOrdererClientForClientConfig(clientConfig)
}

func (order *OrderEnv) newOrdererClientForClientConfig(clientConfig comm.ClientConfig) (*OrdererClient, error) {
	address := order.OrdererAddress
	override := order.OrdererTLSHostnameOverride
	gClient, err := comm.NewGRPCClient(clientConfig)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create OrdererClient from config")
	}
	oClient := &OrdererClient{
		commonClient: commonClient{
			GRPCClient: gClient,
			address:    address,
			sn:         override}}
	return oClient, nil
}

// Broadcast returns a broadcast client for the AtomicBroadcast service
func (oc *OrdererClient) Broadcast() (ab.AtomicBroadcast_BroadcastClient, error) {
	conn, err := oc.commonClient.NewConnection(oc.address, oc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("orderer client failed to connect to %s", oc.address))
	}
	// TODO: check to see if we should actually handle error before returning
	return ab.NewAtomicBroadcastClient(conn).Broadcast(context.TODO())
}

var countorder = 1

func (order *OrderEnv) GetConfig() (clientConfig comm.ClientConfig, err error) {
	clientConfig = comm.ClientConfig{}

	clientConfig.Timeout = order.OrdererConnTimeout
	secOpts := &comm.SecureOptions{
		UseTLS:            order.OrdererTLS,
		RequireClientCert: order.OrdererTLSClientAuthRequired,
	}
	if secOpts.UseTLS {
		caPEM, res := ioutil.ReadFile(utils.ConvertToAbsPath(order.OrdererTLSRootCertFile))
		if res != nil {
			err = errors.WithMessage(res, "unable to load orderer.tls.rootcert.file")
			return
		}
		secOpts.ServerRootCAs = [][]byte{caPEM}
	}
	if secOpts.RequireClientCert {
		path := utils.GetReplaceAbsPath(order.OrdererTLSClientKeyFile, order.OrdererTLSKeyFile)
		keyPEM, res := ioutil.ReadFile(path)
		if res != nil {
			err = errors.WithMessage(res, "unable to load orderer.tls.clientKey.file")
			return
		}
		secOpts.Key = keyPEM
		path = utils.GetReplaceAbsPath(order.OrdererTLSClientCertFile, order.OrdererTLSCertFile)
		certPEM, res := ioutil.ReadFile(path)
		if res != nil {
			err = errors.WithMessage(res, "unable to load orderer.tls.clientCert.file")

			return
		}
		secOpts.Certificate = certPEM
	}
	clientConfig.SecOpts = secOpts

	logger.Debug("orderer GetConfig  第", countorder, "次", order, "connTimeout", order.OrdererConnTimeout)
	countorder++
	return
}
