package peerex

import (

	// "hyperledger-fabric-sdk-go/peerex/common"

	cb "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"

	"github.com/pkg/errors"
)

type BroadcastClient interface {
	//Send data to orderer
	Send(env *cb.Envelope) error
	Close() error
}

type broadcastClient struct {
	client ab.AtomicBroadcast_BroadcastClient
}

// GetBroadcastClient creates a simple instance of the BroadcastClient interface
func (order *OrderEnv) GetBroadcastClient() (BroadcastClient, error) {

	var ordererClient *OrdererClient
	var err error

	ordererClient, err = order.NewordererClientForAddress()

	if err != nil {
		return nil, err
	}

	bc, err := ordererClient.Broadcast()
	if err != nil {
		return nil, err
	}

	return &broadcastClient{client: bc}, nil
}

func (s *broadcastClient) getAck() error {
	msg, err := s.client.Recv()
	if err != nil {
		return err
	}
	if msg.Status != cb.Status_SUCCESS {
		return errors.Errorf("got unexpected status: %v -- %s", msg.Status, msg.Info)
	}
	return nil
}

//Send data to orderer
func (s *broadcastClient) Send(env *cb.Envelope) error {
	if err := s.client.Send(env); err != nil {
		return errors.WithMessage(err, "could not send")
	}

	err := s.getAck()

	return err
}

func (s *broadcastClient) Close() error {
	return s.client.CloseSend()
}
