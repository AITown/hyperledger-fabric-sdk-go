/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peerex

import (
	pb "github.com/hyperledger/fabric/protos/peer"
)

func (peer *PeerEnv) NewEndorserClient() pb.EndorserClient {
	return pb.NewEndorserClient(peer.Connect)
}
