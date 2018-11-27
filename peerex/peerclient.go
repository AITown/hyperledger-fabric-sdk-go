/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peerex

import (
	"context"
	"crypto/tls"
	"fmt"

	// "hyperledger-fabric-sdk-go/peerex/api"
	"hyperledger-fabric-sdk-go/utils"
	"io/ioutil"

	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/peer/common"

	"github.com/hyperledger/fabric/peer/common/api"
	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
)

// PeerClient represents a client for communicating with a peer
type PeerClient struct {
	commonClient
}
type commonClient struct {
	*comm.GRPCClient
	address string
	sn      string
}

// NewPeerClientForAddress creates an instance of a PeerClient using the
// provided peer address and, if TLS is enabled, the TLS root cert file
func (peer *OnePeer) NewPeerClientForAddress() (*PeerClient, error) {

	clientConfig, err := peer.GetConfig()
	if err != nil {
		return nil, err
	}

	return peer.newPeerClientForClientConfig(clientConfig)
}

func (peer *OnePeer) newPeerClientForClientConfig(clientConfig comm.ClientConfig) (*PeerClient, error) {
	address := peer.PeerAddresses
	override := peer.PeerTLSHostnameOverride
	gClient, err := comm.NewGRPCClient(clientConfig)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create PeerClient from config")
	}
	pClient := &PeerClient{
		commonClient: commonClient{
			GRPCClient: gClient,
			address:    address,
			sn:         override}}
	return pClient, nil
}

// Endorser returns a client for the Endorser service
func (pc *PeerClient) Endorser() (pb.EndorserClient, error) {
	conn, err := pc.commonClient.NewConnection(pc.address, pc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("endorser client failed to connect to %s", pc.address))
	}
	return pb.NewEndorserClient(conn), nil
}

// Deliver returns a client for the Deliver service
func (pc *PeerClient) Deliver() (pb.Deliver_DeliverClient, error) {
	logger.Debug("deliver client  connect to %s", pc.address)
	conn, err := pc.commonClient.NewConnection(pc.address, pc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("deliver client failed to connect to %s", pc.address))
	}
	return pb.NewDeliverClient(conn).Deliver(context.TODO())
}

// PeerDeliver returns a client for the Deliver service for peer-specific use
// cases (i.e. DeliverFiltered)
func (pc *PeerClient) PeerDeliver() (api.PeerDeliverClient, error) {
	logger.Debug("PeerDeliver client  connect to %s", pc.address)
	conn, err := pc.commonClient.NewConnection(pc.address, pc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("deliver client failed to connect to %s", pc.address))
	}
	pbClient := pb.NewDeliverClient(conn)
	return &common.PeerDeliverClient{Client: pbClient}, nil
}

// Admin returns a client for the Admin service
func (pc *PeerClient) Admin() (pb.AdminClient, error) {
	logger.Debug("admin client  connect to %s", pc.address)
	conn, err := pc.commonClient.NewConnection(pc.address, pc.sn)
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("admin client failed to connect to %s", pc.address))
	}
	return pb.NewAdminClient(conn), nil
}

// Certificate returns the TLS client certificate (if available)
func (pc *PeerClient) Certificate() tls.Certificate {
	return pc.commonClient.Certificate()
}

// GetEndorserClient returns a new endorser client. If the both the address and
// tlsRootCertFile are not provided, the target values for the client are taken
// from the configuration settings for "peer.address" and
// "peer.tls.rootcert.file"
func (peer *OnePeer) GetEndorserClient() (pb.EndorserClient, error) {
	peerClient, err := peer.NewPeerClientForAddress()

	if err != nil {
		return nil, err
	}
	return peerClient.Endorser()
}

// GetCertificate returns the client's TLS certificate
func (peer *OnePeer) GetCertificate() (tls.Certificate, error) {
	// peerClient, err := NewPeerClientFromEnv()
	peerClient, err := peer.NewPeerClientForAddress()
	if err != nil {
		return tls.Certificate{}, err
	}
	return peerClient.Certificate(), nil
}

// GetAdminClient returns a new admin client.  The target address for
// the client is taken from the configuration setting "peer.address"
func (peer *OnePeer) GetAdminClient() (pb.AdminClient, error) {
	// peerClient, err := NewPeerClientFromEnv()
	peerClient, err := peer.NewPeerClientForAddress()
	if err != nil {
		return nil, err
	}
	return peerClient.Admin()
}

// GetDeliverClient returns a new deliver client. If both the address and
// tlsRootCertFile are not provided, the target values for the client are taken
// from the configuration settings for "peer.address" and
// "peer.tls.rootcert.file"
func (peer *OnePeer) GetDeliverClient() (pb.Deliver_DeliverClient, error) {
	var peerClient *PeerClient
	var err error
	peerClient, err = peer.NewPeerClientForAddress()

	if err != nil {
		return nil, err
	}
	return peerClient.Deliver()
}

// GetPeerDeliverClient returns a new deliver client. If both the address and
// tlsRootCertFile are not provided, the target values for the client are taken
// from the configuration settings for "peer.address" and
// "peer.tls.rootcert.file"
func (peer *OnePeer) GetPeerDeliverClient() (api.PeerDeliverClient, error) {
	var peerClient *PeerClient
	var err error

	peerClient, err = peer.NewPeerClientForAddress()
	if err != nil {
		return nil, err
	}
	return peerClient.PeerDeliver()
}

var conutpeer = 0

func (peer *OnePeer) GetConfig() (clientConfig comm.ClientConfig, err error) {
	clientConfig = comm.ClientConfig{}
	clientConfig.Timeout = peer.PeerClientConnTimeout
	secOpts := &comm.SecureOptions{
		UseTLS:            peer.PeerTLS,
		RequireClientCert: peer.PeerTLSClientAuthRequired,
	}
	if secOpts.UseTLS {
		caPEM, res := ioutil.ReadFile(utils.ConvertToAbsPath(peer.PeerTLSRootCertFile))
		if res != nil {
			err = errors.WithMessage(res, "can not load peer root file")
			return
		}
		secOpts.ServerRootCAs = [][]byte{caPEM}
	}
	if secOpts.RequireClientCert {
		path := utils.GetReplaceAbsPath(peer.PeerTLSClientKeyFile, peer.PeerTLSKeyFile)
		keyPEM, res := ioutil.ReadFile(path)
		if res != nil {
			err = errors.WithMessage(res, "unable to load peer.tls.clientKey.file")
			return
		}
		secOpts.Key = keyPEM
		path = utils.GetReplaceAbsPath(peer.PeerTLSClientCertFile, peer.PeerTLSCertFile)
		certPEM, res := ioutil.ReadFile(path)
		if res != nil {
			err = errors.WithMessage(res, "unable to load peer.tls.clientCert.file")
			return
		}
		secOpts.Certificate = certPEM
	}
	clientConfig.SecOpts = secOpts

	logger.Debug("get peer config 第", conutpeer, "次", peer, "connTimeout", peer.PeerClientConnTimeout)
	conutpeer++
	return
}

// PeerDeliverClient holds the necessary information to connect a client
// to a peer deliver service
// type PeerDeliverClient struct {
// 	Client pb.DeliverClient
// }

// // Deliver connects the client to the Deliver RPC
// func (dc PeerDeliverClient) Deliver(ctx context.Context, opts ...grpc.CallOption) (Deliver, error) {
// 	d, err := dc.Client.Deliver(ctx, opts...)
// 	return d, err
// }

// // DeliverFiltered connects the client to the DeliverFiltered RPC
// func (dc PeerDeliverClient) DeliverFiltered(ctx context.Context, opts ...grpc.CallOption) (Deliver, error) {
// 	df, err := dc.Client.DeliverFiltered(ctx, opts...)
// 	return df, err
// }
