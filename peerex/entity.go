package peerex

import (
	"hyperledger-fabric-sdk-go/msp"
	"time"

	fmsp "github.com/hyperledger/fabric/msp"
	"google.golang.org/grpc"
)

// const (
// 	Query = iota
// 	Invoke
// )

type NodeEnv struct {
	Address          string
	HostnameOverride string
	ConnTimeout      time.Duration

	TLS          bool // 是否启用TLS 连接节点 默认是false
	RootCertFile string

	Connect *grpc.ClientConn
}

//OrderEnv 节点的数据
type OrderEnv struct {
	NodeEnv
}

type PeerEnv struct {
	NodeEnv
}

//PeerEnv 节点的数据
type PeersEnv struct {
	Peers []*PeerEnv
}

type ChaincodeEnv struct {
	Function      string   //方法名 格式:Function :query 如果为空,但如果args的len>1 则默认是invoke  否则是query
	args          []string //方法的参数 格式:args:[]string{"a"} 代表查询a的值 跟方法名要匹配
	ChaincodeName string   //
	ChannelID     string   //channel 的名称
	Signer        fmsp.SigningIdentity
}

//RPCBuilder rpc客户端公共数据
type rPCBuilder struct {
	*ChaincodeEnv
	*msp.MspEnv
	*OrderEnv
	*PeersEnv
}

func (p *PeersEnv) GetPeerAddresses() []string {
	if p == nil || p.Peers == nil {
		return nil
	}
	add := []string{}
	for _, a := range p.Peers {
		add = append(add, a.Address)
	}
	return add
}
