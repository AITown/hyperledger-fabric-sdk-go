package peerex

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/hyperledger/fabric/msp"
	ccapi "github.com/hyperledger/fabric/peer/chaincode/api"

	fcommon "github.com/hyperledger/fabric/peer/common"
	"github.com/hyperledger/fabric/peer/common/api"
	pb "github.com/hyperledger/fabric/protos/peer"
)

const (
	Query = iota
	Invoke
)

//OrderEnv 节点的数据
type OrderEnv struct {
	OrdererTLS                   string // 是否启用TLS 连接order节点 默认是false
	orderertls                   bool
	OrdererAddress               string // 如果需要跟order通讯 ，order的地址
	OrdererTLSHostnameOverride   string
	OrdererConnTimeout           time.Duration
	OrdererTLSClientAuthRequired string
	orderertlsclientauth         bool
	OrdererTLSRootCertFile       string
	OrdererTLSClientKeyFile      string
	OrdererTLSClientCertFile     string
}

//PeerEnv 节点的数据
type PeerEnv struct {
	PeerAddresses             []string //需要连接的peer的地址
	PeerClientConnTimeout     time.Duration
	PeerTLS                   string   //是否启用tls
	peertls                   bool     //是否启用tls 转化PeerTLS为bool
	PeerTLSRootCertFile       []string //如果启用PeerTLS, 则指向要连接到的peer的TLS根证书文件的路径。指定的证书的顺序和数量应与peerAddresses匹配
	PeerTLSHostnameOverride   []string //每一个PeerAddresses所对应的docker 容器中的节点名称 如0.0.0.0:7051->peer0.org1.example.com
	PeerTLSClientAuthRequired string   // 默认是false,如果是true,则需要PeerTLSClientKeyFile   PeerTLSClientCertFile 的值
	peertlsclientauth         bool     // 默认是false,如果是true,则需要PeerTLSClientKeyFile   PeerTLSClientCertFile 的值
	PeerTLSClientKeyFile      string
	PeerTLSClientCertFile     string
	PeerTLSCertFile           string
	PeerTLSKeyFile            string

	//peerBccspSwFileKeyStoreKeyStore string
}

//MspEnv 组织信息
type MspEnv struct {
	PeerLocalMspID    string
	PeerMspConfigPath string
	PeerLocalMspType  string //"bccsp", "idemix"  默认bccsp
}

//RPCBuilder rpc客户端公共数据
type RPCBuilder struct {
	Function            string   //方法名 格式:Function :query 如果为空,但如果args的len>1 则默认是invoke  否则是query
	args                []string //方法的参数 格式:args:[]string{"a"} 代表查询a的值 跟方法名要匹配
	ChaincodeName       string   //
	ChaincodeVersion    string
	ChannelID           string        //channel 的名称
	Escc                string        //指定背书的系统chaincode 默认escc
	Vscc                string        //指定校验的系统chaincode 默认vscc
	WaitForEvent        bool          //是否等待每一个peer节点的消息回执 在invoke是配置
	WaitForEventTimeout time.Duration //如果waitForEvent是true 则可以设置一个超时时间 默认30S

	MspEnv
	OrderEnv
	PeerEnv
}

// ChaincodeCmdFactory holds the clients used by ChaincodeCmd
type ChaincodeCmdFactory struct {
	EndorserClients []pb.EndorserClient
	DeliverClients  []api.PeerDeliverClient
	Certificate     tls.Certificate
	Signer          msp.SigningIdentity
	BroadcastClient fcommon.BroadcastClient
}
type deliverGroup struct {
	Clients     []*deliverClient
	Certificate tls.Certificate
	ChannelID   string
	TxID        string
	mutex       sync.Mutex
	Error       error
	wg          sync.WaitGroup
}

// deliverClient holds the client/connection related to a specific
// peer. The address is included for logging purposes
type deliverClient struct {
	Client     api.PeerDeliverClient
	Connection ccapi.Deliver
	Address    string
}
