/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peerex

import (
	"crypto/tls"
	"time"

	"google.golang.org/grpc"

	pb "github.com/hyperledger/fabric/protos/peer"
)

type GRPCClient struct {
	// TLS configuration used by the grpc.ClientConn
	tlsConfig *tls.Config
	// Options for setting up new connections
	dialOpts []grpc.DialOption
	// Duration for which to block while established a new connection
	timeout time.Duration
	// Maximum message size the client can receive
	maxRecvMsgSize int
	// Maximum message size the client can send
	maxSendMsgSize int
}

func (peer *PeerEnv) NewEndorserClient() pb.EndorserClient {
	return pb.NewEndorserClient(peer.Connect)
}
