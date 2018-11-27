package peerex

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"path/filepath"
	"time"

	mspex "hyperledger-fabric-sdk-go/msp"
	"hyperledger-fabric-sdk-go/utils"

	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/peer/common/api"
	fcommon "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
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
func (o *OrderEnv) verify() error {
	if o == nil {
		return errors.New("orderer 节点配置不能为空")
	}
	if utils.IsNullOrEmpty(o.OrdererAddress) || utils.IsNullOrEmpty(o.OrdererTLSHostnameOverride) {
		return errors.New("OrdererAddress，OrdererTLSHostnameOverride  不能为空")
	}
	if o.OrdererTLS {
		if utils.IsNullOrEmpty(o.OrdererTLSRootCertFile) {
			return errors.New("OrdererTLSRootCertFile  不能为空")
		}
	}

	if o.OrdererConnTimeout == time.Duration(0) {
		o.OrdererConnTimeout = defaultTimeout
	}

	logger.Debug("set PeerClientConnTimeout", o.OrdererConnTimeout)
	return nil
}
func (p *OnePeer) verify() error {
	if p == nil {
		return errors.New("peer 节点配置不能为空")
	}
	if utils.IsNullOrEmpty(p.PeerTLSHostnameOverride) || utils.IsNullOrEmpty(p.PeerAddresses) {
		return errors.New("PeerTLSHostnameOverride,PeerAddresses 不能为空")
	}
	if p.PeerTLS {
		if utils.IsNullOrEmpty(p.PeerTLSRootCertFile) {
			return errors.New("PeerTLSRootCertFile 不能为空")
		}
	}
	if p.PeerClientConnTimeout == time.Duration(0) {
		p.PeerClientConnTimeout = defaultTimeout
	}

	logger.Debug("set PeerClientConnTimeout", p.PeerClientConnTimeout)
	return nil
}

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
	p := &OnePeer{}

	p.PeerClientConnTimeout = viper.GetDuration(peerClientconntimeout)

	p.PeerTLS = viper.GetBool(peerTLSEnabled)
	p.PeerTLSClientAuthRequired = viper.GetBool(peerTLSClientAuthRequired)
	p.PeerTLSCertFile = viper.GetString(peerTLSCertFile)
	p.PeerTLSKeyFile = viper.GetString(peerTLSKeyFile)
	p.PeerTLSClientCertFile = viper.GetString(peerTLSClientCertFile)
	p.PeerTLSClientKeyFile = viper.GetString(peerTLSClientKeyFile)

	r.Peers = append(r.Peers, p)
	//msp
	r.MspID = viper.GetString(peerLocalMspID)
	r.MspConfigPath = viper.GetString(peerMspConfigPath)
	r.MspType = viper.GetString(peerLocalMspType)

	//order
	r.OrdererConnTimeout = viper.GetDuration(ordererConnTimeout)
	r.OrdererTLS = viper.GetBool(ordererTLS)
	r.OrdererTLSClientAuthRequired = viper.GetBool(ordererTLSClientAuthRequired)
	r.OrdererAddress = viper.GetString(ordererEndpoint)
	r.OrdererTLSHostnameOverride = viper.GetString(ordererTLSHostnameOverride)
	r.OrdererTLSClientCertFile = viper.GetString(ordererTLSClientCertFile)
	r.OrdererTLSClientKeyFile = viper.GetString(ordererTLSClientKeyFile)
	r.OrdererTLSRootCertFile = viper.GetString(ordererTLSRootCertFile)

	return r

}

//InitConfig 初始化配置变量 暂时不需要
func (r *rPCBuilder) InitConfig() {
	logger.Debug("viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))

	//peer
	//peerAddress  peerTLSRootCertFile peerTLSServerhostOverride 在invoke时不做变化
	connttime := viper.GetDuration(peerClientconntimeout)

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
	connttime = viper.GetDuration(ordererConnTimeout)
	if r.OrdererConnTimeout != connttime {
		viper.Set(ordererConnTimeout, r.OrdererConnTimeout)
	}
	viper.Set(ordererTLS, r.OrdererTLS)
	viper.Set(ordererTLSClientAuthRequired, r.OrdererTLSClientAuthRequired)
	if r.OrdererAddress != "" {
		viper.Set(ordererEndpoint, r.OrdererAddress)
	}
	if r.OrdererTLSHostnameOverride != "" {
		viper.Set(ordererTLSHostnameOverride, r.OrdererTLSHostnameOverride)
	}
	if r.OrdererTLSClientCertFile != "" {
		viper.Set(ordererTLSClientCertFile, r.OrdererTLSClientCertFile)
	}
	if r.OrdererTLSClientKeyFile != "" {
		viper.Set(ordererTLSClientKeyFile, r.OrdererTLSClientKeyFile)
	}
	if r.OrdererTLSRootCertFile != "" {
		viper.Set(ordererTLSRootCertFile, r.OrdererTLSRootCertFile)
	}

}

//InitFactory 初始化chaincode命令工厂
func (r *rPCBuilder) InitFactory(invoke, isEndorserRequired, isOrdererRequired bool) (*ChaincodeFactory, error) {
	var (
		err             error
		endorserClients []pb.EndorserClient
		deliverClients  []api.PeerDeliverClient
		// tlsRootCertFiles     = r.PeerTLSRootCertFile
		// peerAddresses        = r.PeerAddresses
		// peerhostoverrides    = r.PeerTLSHostnameOverride
		// ordererAddresses = r.OrdererAddress
		// ordererhostoverrides = r.OrdererTLSHostnameOverride
	)
	//背书请求 如果需要跟endorser通信，那么创建endorserClient，参见peerclient.go的NewPeerClientFromEnv函数。
	if isEndorserRequired {

		for _, peer := range r.Peers {
			//error getting endorser client for query: endorser client failed to connect to
			//path: failed to create new connection: context deadline exceeded
			logger.Debug("common.GetEndorserClientFnc override:", peer.PeerTLSHostnameOverride)
			endorserClient, err := peer.GetEndorserClient()
			if err != nil {
				return nil, errors.WithMessage(err, fmt.Sprintf("error getting endorser client "))
			}

			endorserClients = append(endorserClients, endorserClient)
			deliverClient, err := peer.GetPeerDeliverClient()
			if err != nil {
				return nil, errors.WithMessage(err, fmt.Sprintf("error getting deliver client "))
			}
			deliverClients = append(deliverClients, deliverClient)
		}

		if len(endorserClients) == 0 {
			return nil, errors.New("no endorser clients retrieved - this might indicate a bug")
		}
	}
	peer := r.Peers[0]
	certificate, err := peer.GetCertificate()
	if err != nil {
		return nil, errors.WithMessage(err, "error getting client cerificate")
	}

	//signer, err := GetDefaultSignerFnc()
	signer, err := mspex.GetSigningIdentity()
	if err != nil {
		return nil, errors.WithMessage(err, "error getting default signer")
	}

	var broadcastClient BroadcastClient
	// 如果需要跟orderer通信，那么创建跟orderer交互的BroadcastClient。
	// 如果配置没有指定orderer的地址，那么使用GetOrdererEndpointOfChainFnc函数获取所有orderer的地址，取第一个作为通信orderer，调用GetBroadcastClientFnc函数获取BroadcastClient，
	// 如果指定了orderer地址，那么直接调用GetBroadcastClientFnc获取BroadcastClient。

	if isOrdererRequired {
		// if len(ordererAddresses) == 0 {
		// 	if len(endorserClients) == 0 {
		// 		return nil, errors.New("orderer is required, but no ordering endpoint or endorser client supplied")
		// 	}

		// 	endorserClient := endorserClients[0]
		// 	orderingEndpoints, err := GetOrdererEndpointOfChainFnc(r.ChannelID, signer, endorserClient)
		// 	if err != nil {
		// 		return nil, errors.WithMessage(err, fmt.Sprintf("error getting channel (%s) orderer endpoint", r.ChannelID))
		// 	}
		// 	if len(orderingEndpoints) == 0 {
		// 		return nil, errors.Errorf("no orderer endpoints retrieved for channel %s", r.ChannelID)
		// 	}
		// 	logger.Infof("Retrieved channel (%s) orderer endpoint: %s", r.ChannelID, orderingEndpoints[0])
		// 	// override viper env
		// 	viper.Set("orderer.address", orderingEndpoints[0])
		// }
		logger.Debug("----开始根据环境变量构建:GetBroadcastClientFnc")
		broadcastClient, err = r.OrderEnv.GetBroadcastClient()

		if err != nil {
			return nil, errors.WithMessage(err, "error ==getting broadcast client")
		}
	}

	// 根据上面获得信息组装ChaincodeCmdFactory返回
	return &ChaincodeFactory{
		EndorserClients: endorserClients,
		DeliverClients:  deliverClients,
		Signer:          signer,
		BroadcastClient: broadcastClient,
		Certificate:     certificate,
	}, nil
}

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

func newDeliverGroup(deliverClients []api.PeerDeliverClient, peerAddresses []string, certificate tls.Certificate, channelID string, txid string) *deliverGroup {
	clients := make([]*deliverClient, len(deliverClients))
	for i, client := range deliverClients {
		dc := &deliverClient{
			Client:  client,
			Address: peerAddresses[i],
		}
		clients[i] = dc
	}

	dg := &deliverGroup{
		Clients:     clients,
		Certificate: certificate,
		ChannelID:   channelID,
		TxID:        txid,
	}

	return dg
}

// Connect waits for all deliver clients in the group to connect to
// the peer's deliver service, receive an error, or for the context
// to timeout. An error will be returned whenever even a single
// deliver client fails to connect to its peer
func (dg *deliverGroup) Connect(ctx context.Context) error {
	dg.wg.Add(len(dg.Clients))
	for _, client := range dg.Clients {
		go dg.ClientConnect(ctx, client)
	}
	readyCh := make(chan struct{})
	go dg.WaitForWG(readyCh)

	select {
	case <-readyCh:
		if dg.Error != nil {
			err := errors.WithMessage(dg.Error, "failed to connect to deliver on all peers")
			return err
		}
	case <-ctx.Done():
		err := errors.New("timed out waiting for connection to deliver on all peers")
		return err
	}

	return nil
}

// ClientConnect sends a deliver seek info envelope using the
// provided deliver client, setting the deliverGroup's Error
// field upon any error
func (dg *deliverGroup) ClientConnect(ctx context.Context, dc *deliverClient) {
	defer dg.wg.Done()
	df, err := dc.Client.DeliverFiltered(ctx)
	if err != nil {
		err = errors.WithMessage(err, fmt.Sprintf("error connecting to deliver filtered at %s", dc.Address))
		dg.setError(err)
		return
	}
	defer df.CloseSend()
	dc.Connection = df

	envelope := createDeliverEnvelope(dg.ChannelID, dg.Certificate)
	err = df.Send(envelope)
	if err != nil {
		err = errors.WithMessage(err, fmt.Sprintf("error sending deliver seek info envelope to %s", dc.Address))
		dg.setError(err)
		return
	}
}

// Wait waits for all deliver client connections in the group to
// either receive a block with the txid, an error, or for the
// context to timeout
func (dg *deliverGroup) Wait(ctx context.Context) error {
	if len(dg.Clients) == 0 {
		return nil
	}

	dg.wg.Add(len(dg.Clients))
	for _, client := range dg.Clients {
		go dg.ClientWait(client)
	}
	readyCh := make(chan struct{})
	go dg.WaitForWG(readyCh)

	select {
	case <-readyCh:
		if dg.Error != nil {
			err := errors.WithMessage(dg.Error, "failed to receive txid on all peers")
			return err
		}
	case <-ctx.Done():
		err := errors.New("timed out waiting for txid on all peers")
		return err
	}

	return nil
}

// ClientWait waits for the specified deliver client to receive
// a block event with the requested txid
func (dg *deliverGroup) ClientWait(dc *deliverClient) {
	defer dg.wg.Done()
	for {
		resp, err := dc.Connection.Recv()

		if err != nil {
			err = errors.WithMessage(err, fmt.Sprintf("error receiving from deliver filtered at %s", dc.Address))
			dg.setError(err)
			return
		}
		switch r := resp.Type.(type) {
		case *pb.DeliverResponse_FilteredBlock:
			filteredTransactions := r.FilteredBlock.FilteredTransactions
			for _, tx := range filteredTransactions {
				if tx.Txid == dg.TxID {
					logger.Infof("txid [%s] committed with status (%s) at %s", dg.TxID, tx.TxValidationCode, dc.Address)
					return
				}
			}
		case *pb.DeliverResponse_Status:
			err = errors.Errorf("deliver completed with status (%s) before txid received at %s", r.Status, dc.Address)
			dg.setError(err)
			return
		default:
			err = errors.Errorf("received unexpected response type (%T) from %s", r, dc.Address)
			dg.setError(err)
			return
		}
	}
}

// WaitForWG waits for the deliverGroup's wait group and closes
// the channel when ready
func (dg *deliverGroup) WaitForWG(readyCh chan struct{}) {
	dg.wg.Wait()
	close(readyCh)
}

// setError serializes an error for the deliverGroup
func (dg *deliverGroup) setError(err error) {
	dg.mutex.Lock()
	dg.Error = err
	dg.mutex.Unlock()
}

func createDeliverEnvelope(channelID string, certificate tls.Certificate) *fcommon.Envelope {
	var tlsCertHash []byte
	// check for client certificate and create hash if present
	if len(certificate.Certificate) > 0 {
		tlsCertHash = utils.ComputeSHA256(certificate.Certificate[0])
	}

	start := &ab.SeekPosition{
		Type: &ab.SeekPosition_Newest{
			Newest: &ab.SeekNewest{},
		},
	}

	stop := &ab.SeekPosition{
		Type: &ab.SeekPosition_Specified{
			Specified: &ab.SeekSpecified{
				Number: math.MaxUint64,
			},
		},
	}

	seekInfo := &ab.SeekInfo{
		Start:    start,
		Stop:     stop,
		Behavior: ab.SeekInfo_BLOCK_UNTIL_READY,
	}

	env, err := protoutils.CreateSignedEnvelopeWithTLSBinding(
		fcommon.HeaderType_DELIVER_SEEK_INFO, channelID, mspex.NewSigner(),
		seekInfo, int32(0), uint64(0), tlsCertHash)
	// env, err := CreateSignedEnvelopeWithTLSBinding(
	// 	fcommon.HeaderType_DELIVER_SEEK_INFO, channelID, localmsp.NewSigner(),
	// 	seekInfo, int32(0), uint64(0), tlsCertHash)
	if err != nil {
		logger.Errorf("Error signing envelope: %s", err)
		return nil
	}

	return env
}
