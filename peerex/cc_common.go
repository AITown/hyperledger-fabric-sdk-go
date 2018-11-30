package peerex

import (
	"crypto/tls"
	"fmt"
	"path/filepath"
	"time"

	mspex "hyperledger-fabric-sdk-go/msp"
	"hyperledger-fabric-sdk-go/utils"

	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/peer/common/api"
	fcommon "github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
	protoutils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	defaultTimeout = 30 * time.Second
)

const (
	//peer
	peerbase                        = "peer"
	peerAddress                     = peerbase + ".address"
	peerClientconntimeout           = peerbase + ".client.conntimeout"
	peerTLSEnabled                  = peerbase + ".tls.enabled"
	peerTLSClientAuthRequired       = peerbase + ".tls.clientAuthRequired"
	peerTLSRootCertFile             = peerbase + ".tls.rootcert.file"
	peerTLSClientKeyFile            = peerbase + ".tls.ClientKey.File"
	peerTLSClientCertFile           = peerbase + ".tls.clientCert.File"
	peerTLSCertFile                 = peerbase + ".tls.cert.file"
	peerTLSKeyFile                  = peerbase + ".tls.key.file"
	peerTLSServerhostOverride       = peerbase + ".tls.serverhostoverride"
	peerBccspSwFileKeyStoreKeyStore = peerbase + ".BCCSP.SW.FileKeyStore.KeyStore"

	//msp
	peerLocalMspID    = peerbase + ".localMspId"
	peerMspConfigPath = peerbase + ".mspConfigPath"
	peerLocalMspType  = peerbase + ".localMspType"

	//order 配置
	ordererbase                  = "orderer"
	ordererEndpoint              = ordererbase + ".address"
	ordererTLS                   = ordererbase + ".tls.enabled"
	ordererConnTimeout           = ordererbase + ".client.conntimeout"
	ordererTLSClientAuthRequired = ordererbase + ".tls.clientAuthRequired"
	ordererTLSRootCertFile       = ordererbase + ".tls.rootcert.file"
	ordererTLSClientKeyFile      = ordererbase + ".tls.clientKey.file"
	ordererTLSClientCertFile     = ordererbase + ".tls.clientCert.file"
	ordererTLSHostnameOverride   = ordererbase + ".tls.serverhostoverride"
)

type ChaincodeFactory struct {
	EndorserClients []pb.EndorserClient
	DeliverClients  []api.PeerDeliverClient
	Certificate     tls.Certificate
	Signer          msp.SigningIdentity
	BroadcastClient BroadcastClient
}

//Verify 检查参数正确性 没有的构建默认值
func (r *rPCBuilder) Verify(get bool) error {
	if r.ChannelID == "" {
		return errors.New("channelID 不能为空")
	}
	// we need chaincode name for everything, including deploy
	if r.ChaincodeName == "" {
		return errors.New("ChaincodeName 不能为空")
	}

	//格式:Function :query args:[]string{"a"} 代表查询a的值  如果为空,根据参数get 赋值
	if len(r.args) == 0 {
		return errors.Errorf("%s方法所携带的参数不能为空", r.Function)
	}
	if r.Function == "" {
		if get {
			r.Function = query
			logger.Warning("Using default Function:", query)
		} else {
			r.Function = invoke
			logger.Warning("Using default Function:", invoke)
		}
	}

	if r.WaitForEvent == true && r.WaitForEventTimeout == time.Duration(0) {
		r.WaitForEventTimeout = defaultTimeout
	}
	if len(r.Peers) == 0 {
		return errors.New("没有任何peer节点信息")
	}
	if get {
		if len(r.Peers) > 1 {
			return errors.New("query 目前只支持单节点")
		}
	} else {
		r.OrderEnv.verify()
	}
	for _, p := range r.Peers {
		err := p.verify()
		if err != nil {
			return err
		}
	}
	logger.Debug("检查参数正确性=======down")
	return nil
}
func (node *NodeEnv) verify() error {
	if node == nil {
		return errors.New("orderer 节点配置不能为空")
	}
	if utils.IsNullOrEmpty(node.Address) || utils.IsNullOrEmpty(node.HostnameOverride) {
		return errors.New("Address，HostnameOverride  不能为空")
	}
	if node.TLS {
		if utils.IsNullOrEmpty(node.RootCertFile) {
			return errors.New("OrdererTLSRootCertFile  不能为空")
		}
	}

	if node.ConnTimeout == time.Duration(0) {
		node.ConnTimeout = defaultTimeout
	}

	logger.Debug("set PeerClientConnTimeout", node.ConnTimeout)
	return nil
}

// func (o *OrderEnv) verify() error {
// 	if o == nil {
// 		return errors.New("orderer 节点配置不能为空")
// 	}
// 	if utils.IsNullOrEmpty(o.OrdererAddress) || utils.IsNullOrEmpty(o.OrdererTLSHostnameOverride) {
// 		return errors.New("OrdererAddress，OrdererTLSHostnameOverride  不能为空")
// 	}
// 	if o.OrdererTLS {
// 		if utils.IsNullOrEmpty(o.OrdererTLSRootCertFile) {
// 			return errors.New("OrdererTLSRootCertFile  不能为空")
// 		}
// 	}

// 	if o.OrdererConnTimeout == time.Duration(0) {
// 		o.OrdererConnTimeout = defaultTimeout
// 	}

// 	logger.Debug("set PeerClientConnTimeout", o.OrdererConnTimeout)
// 	return nil
// }
// func (p *OnePeer) verify() error {
// 	if p == nil {
// 		return errors.New("peer 节点配置不能为空")
// 	}
// 	if utils.IsNullOrEmpty(p.PeerTLSHostnameOverride) || utils.IsNullOrEmpty(p.PeerAddresses) {
// 		return errors.New("PeerTLSHostnameOverride,PeerAddresses 不能为空")
// 	}
// 	if p.PeerTLS {
// 		if utils.IsNullOrEmpty(p.PeerTLSRootCertFile) {
// 			return errors.New("PeerTLSRootCertFile 不能为空")
// 		}
// 	}
// 	if p.PeerClientConnTimeout == time.Duration(0) {
// 		p.PeerClientConnTimeout = defaultTimeout
// 	}

// 	logger.Debug("set PeerClientConnTimeout", p.PeerClientConnTimeout)
// 	return nil
// }

func InitCrypto(m *mspex.MspEnv) error {
	// var mspMgrConfigDir = common.GetPath(peerMspConfigPath)
	// var mspID = viper.GetString(peerLocalMspID)
	// var mspType = viper.GetString(peerLocalMspType)
	if m == nil {
		return errors.New("MspEnv is null")
	}
	err := m.Verify()
	if err != nil {
		return err
	}

	logger.Debugf("get config MspConfigPath:%s==mspID:%s==mspType:%s \n", m.MspConfigPath, m.MspID, m.MspType)

	_, err = m.InitCrypto()
	if err != nil {
		// Handle errors reading the config file
		logger.Errorf("Cannot run peer because %s", err.Error())
	}
	return err
}

//InitWithFile InitWithFile  未实现
func InitWithFile(path string) Handle {
	// peerpath := filepath.Join(os.Getenv("GOPATH"), "src/hyperledger-fabric-sdk-go")
	// if err := utils.InitViper("core", "core", "./", peerpath); err != nil {
	// 	fmt.Println("utils.InitPeerViper faile:", err)
	// }
	r := NewRpcBuilder()
	// p := &OnePeer{}

	// p.PeerClientConnTimeout = viper.GetDuration(peerClientconntimeout)

	// p.PeerTLS = viper.GetBool(peerTLSEnabled)
	// p.PeerTLSClientAuthRequired = viper.GetBool(peerTLSClientAuthRequired)
	// p.PeerTLSCertFile = viper.GetString(peerTLSCertFile)
	// p.PeerTLSKeyFile = viper.GetString(peerTLSKeyFile)
	// p.PeerTLSClientCertFile = viper.GetString(peerTLSClientCertFile)
	// p.PeerTLSClientKeyFile = viper.GetString(peerTLSClientKeyFile)

	// r.Peers = append(r.Peers, p)
	// //msp
	// r.MspID = viper.GetString(peerLocalMspID)
	// r.MspConfigPath = viper.GetString(peerMspConfigPath)
	// r.MspType = viper.GetString(peerLocalMspType)

	// //order
	// r.OrdererConnTimeout = viper.GetDuration(ordererConnTimeout)
	// r.OrdererTLS = viper.GetBool(ordererTLS)
	// r.OrdererTLSClientAuthRequired = viper.GetBool(ordererTLSClientAuthRequired)
	// r.OrdererAddress = viper.GetString(ordererEndpoint)
	// r.OrdererTLSHostnameOverride = viper.GetString(ordererTLSHostnameOverride)
	// r.OrdererTLSClientCertFile = viper.GetString(ordererTLSClientCertFile)
	// r.OrdererTLSClientKeyFile = viper.GetString(ordererTLSClientKeyFile)
	// r.OrdererTLSRootCertFile = viper.GetString(ordererTLSRootCertFile)

	return r

}

//InitConfig 初始化配置变量 暂时不需要
func (r *rPCBuilder) InitConfig() {
	logger.Debug("viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))

	//peer
	//peerAddress  peerTLSRootCertFile peerTLSServerhostOverride 在invoke时不做变化
	// connttime := viper.GetDuration(peerClientconntimeout)

	// if r.PeerClientConnTimeout != connttime {
	// 	viper.Set(peerClientconntimeout, r.PeerClientConnTimeout.String())
	// }
	// viper.Set(peerTLSEnabled, r.PeerTLS)
	// viper.Set(peerTLSClientAuthRequired, r.PeerTLSClientAuthRequired)
	// if r.PeerTLSCertFile != "" {
	// 	viper.Set(peerTLSCertFile, r.PeerTLSCertFile)
	// }
	// if r.PeerTLSKeyFile != "" {
	// 	viper.Set(peerTLSKeyFile, r.PeerTLSKeyFile)
	// }

	// if r.PeerTLSClientCertFile != "" {
	// 	viper.Set(peerTLSClientCertFile, r.PeerTLSClientCertFile)
	// }
	// if r.PeerTLSClientKeyFile != "" {
	// 	viper.Set(peerTLSClientKeyFile, r.PeerTLSClientKeyFile)
	// }
	//msp
	if r.MspID != "" {
		viper.Set(peerLocalMspID, r.MspID)
	}
	if r.MspConfigPath != "" {
		viper.Set(peerMspConfigPath, r.MspConfigPath)
	}
	if r.MspType != "" {
		viper.Set(peerLocalMspType, r.MspType)
	}

	//order
	// connttime = viper.GetDuration(ordererConnTimeout)
	// if r.OrdererConnTimeout != connttime {
	// 	viper.Set(ordererConnTimeout, r.OrdererConnTimeout)
	// }
	// viper.Set(ordererTLS, r.OrdererTLS)
	// viper.Set(ordererTLSClientAuthRequired, r.OrdererTLSClientAuthRequired)
	// if r.OrdererAddress != "" {
	// 	viper.Set(ordererEndpoint, r.OrdererAddress)
	// }
	// if r.OrdererTLSHostnameOverride != "" {
	// 	viper.Set(ordererTLSHostnameOverride, r.OrdererTLSHostnameOverride)
	// }
	// if r.OrdererTLSClientCertFile != "" {
	// 	viper.Set(ordererTLSClientCertFile, r.OrdererTLSClientCertFile)
	// }
	// if r.OrdererTLSClientKeyFile != "" {
	// 	viper.Set(ordererTLSClientKeyFile, r.OrdererTLSClientKeyFile)
	// }
	// if r.OrdererTLSRootCertFile != "" {
	// 	viper.Set(ordererTLSRootCertFile, r.OrdererTLSRootCertFile)
	// }

}

//InitFactory 初始化chaincode命令工厂
func (r *rPCBuilder) InitConn(isOrdererRequired bool) error {

	logger.Debug("========InitConn start:============")
	// for _, peer := range r.Peers {
	//error getting endorser client for query: endorser client failed to connect to
	//path: failed to create new connection: context deadline exceeded
	// logger.Debug("common.GetEndorserClientFnc override:", node.HostnameOverride)
	signer, err := mspex.GetSigningIdentity()
	r.ChaincodeEnv.Signer = signer
	if err != nil {
		return errors.WithMessage(err, "error getting default signer")
	}

	for i := 0; i < len(r.Peers); i++ {
		err := r.Peers[i].ClientConn()
		if err != nil {
			return err
		}

		logger.Debug("----order grpc conn----")
	}

	if isOrdererRequired {

		err := r.OrderEnv.ClientConn()
		if err != nil {
			return err
		}
		logger.Debug("----order grpc conn----")
	}
	return nil
}

// //InitFactory 初始化chaincode命令工厂
// func (r *rPCBuilder) InitFactory(isOrdererRequired bool) (*ChaincodeFactory, error) {
// 	var (
// 		err             error
// 		endorserClients []pb.EndorserClient
// 		deliverClients  []api.PeerDeliverClient
// 	)
// 	logger.Debug("========InitFactory start:============")
// 	for _, peer := range r.Peers {
// 		//error getting endorser client for query: endorser client failed to connect to
// 		//path: failed to create new connection: context deadline exceeded
// 		logger.Debug("common.GetEndorserClientFnc override:", peer.HostnameOverride)
// 		endorserClient, err := peer.GetEndorserClient()
// 		if err != nil {
// 			return nil, errors.WithMessage(err, fmt.Sprintf("error getting endorser client "))
// 		}
// 		//背书请求 每一个peer会创建一个 调用endorserClients.ProcessProposal执行invoke query
// 		endorserClients = append(endorserClients, endorserClient)

// 		deliverClient, err := peer.GetPeerDeliverClient()
// 		if err != nil {
// 			return nil, errors.WithMessage(err, fmt.Sprintf("error getting deliver client "))
// 		}
// 		deliverClients = append(deliverClients, deliverClient)
// 	}

// 	if len(endorserClients) == 0 {
// 		return nil, errors.New("no endorser clients retrieved - this might indicate a bug")
// 	}

// 	peer := r.Peers[0]
// 	certificate, err := peer.GetCertificate()
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "error getting client cerificate")
// 	}

// 	//signer, err := GetDefaultSignerFnc()
// 	signer, err := mspex.GetSigningIdentity()
// 	if err != nil {
// 		return nil, errors.WithMessage(err, "error getting default signer")
// 	}

// 	var broadcastClient BroadcastClient
// 	// 如果需要跟orderer通信，那么创建跟orderer交互的BroadcastClient。
// 	if isOrdererRequired {
// 		logger.Debug("----开始根据环境变量构建:GetBroadcastClientFnc")
// 		broadcastClient, err = r.OrderEnv.GetBroadcastClient()

// 		if err != nil {
// 			return nil, errors.WithMessage(err, "error getting broadcast client")
// 		}
// 	}

// 	// 根据上面获得信息组装ChaincodeCmdFactory返回
// 	return &ChaincodeFactory{
// 		EndorserClients: endorserClients,
// 		DeliverClients:  deliverClients,
// 		Signer:          signer,
// 		BroadcastClient: broadcastClient,
// 		Certificate:     certificate,
// 	}, nil
// }

// getChaincodeSpec get chaincode spec from the  pramameters
func (cc *ChaincodeEnv) getChaincodeSpec(args []string) *pb.ChaincodeSpec {
	spec := &pb.ChaincodeSpec{}
	funcname := cc.Function
	input := &pb.ChaincodeInput{}
	input.Args = append(input.Args, []byte(funcname))

	for _, arg := range args {
		input.Args = append(input.Args, []byte(arg))
	}

	logger.Debug("ChaincodeSpec input :", input, " funcname:", funcname)
	var golang = pb.ChaincodeSpec_Type_name[1]
	spec = &pb.ChaincodeSpec{
		Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[golang]),
		// ChaincodeId: &pb.ChaincodeID{Name: cc.ChaincodeName, Version: cc.ChaincodeVersion},
		ChaincodeId: &pb.ChaincodeID{Name: cc.ChaincodeName},
		Input:       input,
	}
	return spec
}

// func newDeliverGroup(deliverClients []api.PeerDeliverClient, peerAddresses []string, certificate tls.Certificate, channelID string, txid string) *deliverGroup {
// 	clients := make([]*deliverClient, len(deliverClients))
// 	for i, client := range deliverClients {
// 		dc := &deliverClient{
// 			Client:  client,
// 			Address: peerAddresses[i],
// 		}
// 		clients[i] = dc
// 	}

// 	dg := &deliverGroup{
// 		Clients:     clients,
// 		Certificate: certificate,
// 		ChannelID:   channelID,
// 		TxID:        txid,
// 	}

// 	return dg
// }

// CreateChaincodeProposalWithTxIDAndTransient creates a proposal from given input
// It returns the proposal and the transaction id associated to the proposal
func CreateChaincodeProposalWithTxIDAndTransient(chainID string, spec *pb.ChaincodeSpec, creator []byte, transientMap map[string][]byte) (*pb.Proposal, string, error) {
	// generate a random nonce
	nonce, err := utils.GetRandomNonce()
	if err != nil {
		return nil, "", err
	}
	txid, err := protoutils.ComputeProposalTxID(nonce, creator)
	if err != nil {
		return nil, "", err
	}
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
	ccHdrExt := &pb.ChaincodeHeaderExtension{ChaincodeId: spec.ChaincodeId}

	ccHdrExtBytes, err := protoutils.Marshal(ccHdrExt)
	if err != nil {
		return nil, "", err
	}

	cisBytes, err := protoutils.Marshal(invocation)
	if err != nil {
		return nil, "", err
	}

	ccPropPayload := &pb.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap}
	ccPropPayloadBytes, err := protoutils.Marshal(ccPropPayload)
	if err != nil {
		return nil, "", err
	}

	// TODO: epoch is now set to zero. This must be changed once we
	// get a more appropriate mechanism to handle it in.
	var (
		epoch     uint64
		timestamp = util.CreateUtcTimestamp()
		typ       = int32(fcommon.HeaderType_ENDORSER_TRANSACTION)
	)

	channelHeader, err := protoutils.Marshal(&fcommon.ChannelHeader{
		Type:      typ,
		TxId:      txid,
		Timestamp: timestamp,
		ChannelId: chainID,
		Extension: ccHdrExtBytes,
		Epoch:     epoch,
	})
	if err != nil {
		return nil, "", err
	}
	signatureHeader, err := protoutils.Marshal(&fcommon.SignatureHeader{
		Nonce:   nonce,
		Creator: creator,
	})

	if err != nil {
		return nil, "", err
	}

	hdr := &fcommon.Header{
		ChannelHeader:   channelHeader,
		SignatureHeader: signatureHeader,
	}

	hdrBytes, err := protoutils.Marshal(hdr)
	if err != nil {
		return nil, "", err
	}
	return &pb.Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}, txid, nil
}

// GetSignedProposal returns a signed proposal given a Proposal message and a signing identity
func GetSignedProposal(prop *pb.Proposal, signer msp.SigningIdentity) (*pb.SignedProposal, error) {
	// check for nil argument
	if prop == nil || signer == nil {
		return nil, fmt.Errorf("Nil arguments")
	}

	propBytes, err := protoutils.Marshal(prop)
	if err != nil {
		return nil, err
	}

	signature, err := signer.Sign(propBytes)
	if err != nil {
		return nil, err
	}

	return &pb.SignedProposal{ProposalBytes: propBytes, Signature: signature}, nil
}

// Serialize returns a byte array representation of this identity
// func (id *identity) Serialize() ([]byte, error) {
// 	// mspIdentityLogger.Infof("Serializing identity %s", id.id)
// 	fmt.Println(`F:\virtualMachineShare\src\github.com\hyperledger\fabric\msp\identities.go Serialize()`, id.id.Mspid)
// 	pb := &pem.Block{Bytes: id.cert.Raw, Type: "CERTIFICATE"}
// 	pemBytes := pem.EncodeToMemory(pb)
// 	if pemBytes == nil {
// 		return nil, errors.New("encoding of identity failed")
// 	}

// 	// We serialize identities by prepending the MSPID and appending the ASN.1 DER content of the cert
// 	sId := &msp.SerializedIdentity{Mspid: id.id.Mspid, IdBytes: pemBytes}
// 	idBytes, err := proto.Marshal(sId)
// 	if err != nil {
// 		return nil, errors.Wrapf(err, "could not marshal a SerializedIdentity structure for identity %s", id.id)
// 	}

// 	return idBytes, nil
// }
