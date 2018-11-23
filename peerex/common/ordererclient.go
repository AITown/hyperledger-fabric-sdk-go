package common

import (
	"context"
	"fmt"

	"github.com/hyperledger/fabric/core/comm"
	ab "github.com/hyperledger/fabric/protos/orderer"
	"github.com/pkg/errors"
)

// OrdererClient represents a client for communicating with an ordering
// service
type OrdererClient struct {
	commonClient
}

func NewordererClientForAddress(address, override string) (*OrdererClient, error) {
	_, _, clientConfig, err := configFromEnv("orderer")
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config for OrdererClient")
	}
	return newOrdererClientForClientConfig(address, override, clientConfig)
}

// NewOrdererClientFromEnv creates an instance of an OrdererClient from the
// global Viper instance
func NewOrdererClientFromEnv() (*OrdererClient, error) {
	address, override, clientConfig, err := configFromEnv("orderer")
	if err != nil {
		return nil, errors.WithMessage(err, "failed to load config for OrdererClient")
	}
	return newOrdererClientForClientConfig(address, override, clientConfig)
	// gClient, err := comm.NewGRPCClient(clientConfig)
	// if err != nil {
	// 	return nil, errors.WithMessage(err, "failed to create OrdererClient from config")
	// }
	// oClient := &OrdererClient{
	// 	commonClient: commonClient{
	// 		GRPCClient: gClient,
	// 		address:    address,
	// 		sn:         override}}
	// return oClient, nil
}

func newOrdererClientForClientConfig(address, override string, clientConfig comm.ClientConfig) (*OrdererClient, error) {
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
