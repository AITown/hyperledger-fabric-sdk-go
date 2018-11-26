package peerex

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"path/filepath"
	"time"

	"hyperledger-fabric-sdk-go/msp/localmsp"
	"hyperledger-fabric-sdk-go/peerex/utils"

	mspex "hyperledger-fabric-sdk-go/msp"

	"github.com/golang/protobuf/proto"

	// "github.com/hyperledger/fabric/common/localmsp"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/peer/common/api"
	fcommon "github.com/hyperledger/fabric/protos/common"

	ab "github.com/hyperledger/fabric/protos/orderer"
	pb "github.com/hyperledger/fabric/protos/peer"
	fprotoutils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	escc        = "escc"
	vscc        = "vscc"
	errorStatus = 400
)

// var localMspType = msp.ProviderTypeToString(msp.FABRIC)

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
func (r *rPCBuilder) Verify(set bool) error {
	if r.ChannelID == "" {
		return errors.New("channelID 不能为空")
	}
	// we need chaincode name for everything, including deploy
	if r.ChaincodeName == "" {
		return errors.New("ChaincodeName 不能为空")
	}
	//格式:Function :query args:[]string{"a"} 代表查询a的值  如果为空,但如果args的len>1 则默认是invoke  否则是query
	if len(r.args) == 0 {
		return errors.Errorf("%s方法所携带的参数不能为空", r.Function)
	}
	if r.Function == "" {
		if len(r.args) == 1 {
			r.Function = query
			logger.Warning("Using default Function:", query)
		} else {
			r.Function = invoke
			logger.Warning("Using default Function:", invoke)
		}
	}
	if r.ChaincodeVersion == "" {
		return errors.Errorf("chaincode version is not provided for %s", r.Function)
	}

	if r.Escc != "" {
		logger.Infof("Using escc %s", r.Escc)
	} else {
		logger.Info("Using default escc")
		r.Escc = escc
	}

	if r.Vscc != "" {
		logger.Infof("Using vscc %s", r.Vscc)
	} else {
		logger.Info("Using default vscc")
		r.Vscc = vscc
	}

	//add by gjf
	if r.WaitForEvent == true && r.WaitForEventTimeout == time.Duration(0) {
		r.WaitForEventTimeout = time.Second * 30
	}

	// if r.PeerClientConnTimeout == time.Duration(0) {
	// 	r.PeerClientConnTimeout = 30 * time.Second
	// }
	if len(r.Peers) == 0 {
		return errors.New("没有任何peer节点信息")
	}
	if !set && len(r.Peers) > 1 {
		return errors.New("query 目前只支持单节点")
	}

	for _, p := range r.Peers {
		err := p.verify(set)
		if err != nil {
			return err
		}
	}
	// if len(r.PeerAddresses) == 0 {
	// 	logger.Info("PeerAddresses is nil")
	// 	r.PeerAddresses = make([]string, 1)
	// }

	logger.Debug("检查参数正确性=======down")
	return nil
}

func (p *OnePeer) verify(invoke bool) error {
	if p.PeerTLS {
		if utils.IsNullOrEmpty(p.PeerTLSRootCertFile) || utils.IsNullOrEmpty(p.PeerTLSHostnameOverride) || utils.IsNullOrEmpty(p.PeerAddresses) {
			return errors.New("PeerTLSRootCertFile，PeerTLSHostnameOverride ，PeerAddresses 不能为空")
		}
	}

	return nil
}

// func verify(m *mspex.MspEnv) error {

// 	if m.MspType == "" {
// 		//mspType = msp.ProviderTypeToString(msp.FABRIC)
// 		m.MspType = localMspType
// 		logger.Warning("MspType is nll use default type : bccsp")
// 	}
// 	m.MspConfigPath = utils.ConvertToAbsPath(m.MspConfigPath)
// 	// if !filepath.IsAbs(m.MspConfigPath) {
// 	// 	return errors.New("msp path is not absolute")
// 	// }
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

//InitWithFile InitWithFile
func InitWithFile(path string) Handle {
	// peerpath := filepath.Join(os.Getenv("GOPATH"), "src/hyperledger-fabric-sdk-go")
	// if err := utils.InitViper("core", "core", "./", peerpath); err != nil {
	// 	fmt.Println("utils.InitPeerViper faile:", err)
	// }
	r := NewRpcBuilder()
	p := OnePeer{}

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

//InitConfig 初始化配置变量
func (r *rPCBuilder) InitConfig() {
	logger.Debug("=====viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))

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
		ordererAddresses = r.OrdererAddress
		// ordererhostoverrides = r.OrdererTLSHostnameOverride
	)
	//背书请求 如果需要跟endorser通信，那么创建endorserClient，参见peerclient.go的NewPeerClientFromEnv函数。
	if isEndorserRequired {

		for _, peer := range r.Peers {
			// address := peer.PeerAddresses
			// rootca := peer.PeerTLSRootCertFile
			// override := peer.PeerTLSHostnameOverride
			//多个peer节点
			// for i, address := range peerAddresses {
			// 	var tlsRootCertFile string
			// 	if tlsRootCertFiles != nil {
			// 		tlsRootCertFile = tlsRootCertFiles[i]
			// 	}
			// 	var override string
			// 	if peerhostoverrides != nil {
			// 		override = peerhostoverrides[i]
			// 	}
			//error getting endorser client for query: endorser client failed to connect to
			//path: failed to create new connection: context deadline exceeded
			logger.Debug("common.GetEndorserClientFnc :override:=", peer.PeerTLSHostnameOverride)
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

	signer, err := GetDefaultSignerFnc(r.MspType)
	if err != nil {
		return nil, errors.WithMessage(err, "error getting default signer")
	}

	var broadcastClient BroadcastClient
	// 如果需要跟orderer通信，那么创建跟orderer交互的BroadcastClient。
	// 如果配置没有指定orderer的地址，那么使用GetOrdererEndpointOfChainFnc函数获取所有orderer的地址，取第一个作为通信orderer，调用GetBroadcastClientFnc函数获取BroadcastClient，
	// 如果指定了orderer地址，那么直接调用GetBroadcastClientFnc获取BroadcastClient。

	if isOrdererRequired {
		if len(ordererAddresses) == 0 {
			if len(endorserClients) == 0 {
				return nil, errors.New("orderer is required, but no ordering endpoint or endorser client supplied")
			}

			endorserClient := endorserClients[0]
			orderingEndpoints, err := GetOrdererEndpointOfChainFnc(r.ChannelID, signer, endorserClient)
			if err != nil {
				return nil, errors.WithMessage(err, fmt.Sprintf("error getting channel (%s) orderer endpoint", r.ChannelID))
			}
			if len(orderingEndpoints) == 0 {
				return nil, errors.Errorf("no orderer endpoints retrieved for channel %s", r.ChannelID)
			}
			logger.Infof("Retrieved channel (%s) orderer endpoint: %s", r.ChannelID, orderingEndpoints[0])
			// override viper env
			viper.Set("orderer.address", orderingEndpoints[0])
		}
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
	// input.Args = make([][]byte, len(args)+1)
	// if len(funcname) == 0 {
	// 	return nil, errors.New("方法名为空")
	// }
	// input.Args[0] = []byte(funcname)
	// for i, x := range args {
	// 	input.Args[i+1] = []byte(x)
	// }

	input.Args = append(input.Args, []byte(funcname))

	for _, arg := range args {
		input.Args = append(input.Args, []byte(arg))
	}

	logger.Debug("ChaincodeSpec input :", input, " funcname:", funcname)
	var golang = pb.ChaincodeSpec_Type_name[1]
	spec = &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[golang]),
		ChaincodeId: &pb.ChaincodeID{Name: cc.ChaincodeName, Version: cc.ChaincodeVersion},
		Input:       input,
	}
	return spec
}

// func (cc *ChaincodeEnv) Query(cf *ChaincodeFactory, args []string) (string, error) {
// 	pb, _, err := cc.handle(cf, false, args)
// 	if err != nil {
// 		return "", nil
// 	}
// 	return string(pb.Payload), nil
// }

// func (cc *ChaincodeEnv) Invoke(cf *ChaincodeFactory, args []string) (string, error) {
// 	_, txid, err := cc.handle(cf, true, args)
// 	if err != nil {
// 		return "", nil
// 	}
// 	return txid, nil
// }

// func (cc *ChaincodeEnv) handle(cf *ChaincodeFactory, invoke bool, args []string) (*pb.ProposalResponse, string, error) {

// 	// call with empty txid to ensure production code generates a txid.
// 	// otherwise, tests can explicitly set their own txid
// 	txID := ""
// 	spec := cc.getChaincodeSpec(args)

// 	//proposalResp, _, err := ChaincodeInvokeOrQuery(spec, rpcCommonDate.ChannelID, txID, false, cf.Signer, cf.Certificate, cf.EndorserClients, cf.DeliverClients, cf.BroadcastClient)
// 	proposalResp, txid, err := cf.ChaincodeInvokeOrQuery(spec, cc.ChannelID, txID, invoke)
// 	if err != nil {
// 		return nil, "", errors.Errorf("%s - proposal response: %v", err, proposalResp)
// 	}

// 	if proposalResp == nil {
// 		return nil, "", errors.New("error during query: received nil proposal response")
// 	}
// 	if proposalResp.Endorsement == nil {
// 		return nil, "", errors.Errorf("endorsement failure during query. response: %v", proposalResp.Response)
// 	}

// 	return proposalResp, txid, nil
// }

// ChaincodeInvokeOrQuery invokes or queries the chaincode. If successful, the
// INVOKE form prints the ProposalResponse to STDOUT, and the QUERY form prints
// the query result on STDOUT. A command-line flag (-r, --raw) determines
// whether the query result is output as raw bytes, or as a printable string.
// The printable form is optionally (-x, --hex) a hexadecimal representation
// of the query response. If the query response is NIL, nothing is output.
//
// NOTE - Query will likely go away as all interactions with the endorser are
// Proposal and ProposalResponses
func (cf *ChaincodeFactory) ChaincodeInvokeOrQuery(spec *pb.ChaincodeSpec, channelID string, txID string, invoke bool) (*pb.ProposalResponse, string, error) {
	var (
		responses []*pb.ProposalResponse
		result    string
		tMap      map[string][]byte
	)

	// Build the ChaincodeInvocationSpec message 创建chaincode执行描述结构，创建proposal
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	creator, err := cf.Signer.Serialize()
	if err != nil {
		return nil, "", errors.WithMessage(err, fmt.Sprintf("error serializing identity for %s", cf.Signer.GetIdentifier()))
	}

	prop, txid, err := fprotoutils.CreateChaincodeProposalWithTxIDAndTransient(fcommon.HeaderType_ENDORSER_TRANSACTION, channelID, invocation, creator, txID, tMap)
	logger.Debug(" ChaincodeInvokeOrQuery fprotoutils.CreateChaincodeProposalWithTxIDAndTransient", txid)
	if err != nil {
		return nil, "", errors.WithMessage(err, "error creating proposal")
	}
	result = txid
	//对proposal签名
	signedProp, err := fprotoutils.GetSignedProposal(prop, cf.Signer)

	if err != nil {
		return nil, "", errors.WithMessage(err, "error creating signed proposal ")
	}
	logger.Debug("ChaincodeInvokeOrQuery fprotoutils.GetSignedProposal==== success")
	for _, endorser := range cf.EndorserClients {
		//使用grpc调用endorserClient.ProcessProposal，触发endorer执行proposal
		proposalResp, err := endorser.ProcessProposal(context.Background(), signedProp)
		if err != nil {
			return nil, "", errors.WithMessage(err, "error endorsing ")
		}

		responses = append(responses, proposalResp)
	}

	if len(responses) == 0 {
		// this should only happen if some new code has introduced a bug
		return nil, "", errors.New("no proposal responses received - this might indicate a bug")
	}
	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status
	proposalResp := responses[0]
	//得到proposalResponse，如果是查询类命令直接返回结果；
	//如果是执行交易类，需要对交易签名CreateSignedTx，然后调用BroadcastClient发送给orderer进行排序，返回response
	if invoke {
		if proposalResp != nil {
			if proposalResp.Response.Status >= errorStatus {
				return proposalResp, "", nil
			}
			// assemble a signed transaction (it's an Envelope message) 对交易签名CreateSignedTx
			env, err := fprotoutils.CreateSignedTx(prop, cf.Signer, responses...)
			if err != nil {
				return proposalResp, "", errors.WithMessage(err, "could not assemble transaction")
			}
			logger.Debug("ChaincodeInvokeOrQuery fprotoutils.CreateSignedTx 成功")

			var dg *deliverGroup
			var ctx context.Context
			if rpcCommonDate.WaitForEvent {
				var cancelFunc context.CancelFunc
				ctx, cancelFunc = context.WithTimeout(context.Background(), rpcCommonDate.WaitForEventTimeout)
				defer cancelFunc()

				padd := rpcCommonDate.PeerEnv.GetPeerAddresses()
				dg = newDeliverGroup(cf.DeliverClients, padd, cf.Certificate, channelID, txid)
				logger.Debug("ChaincodeInvokeOrQuery newDeliverGroup 成功")

				// connect to deliver service on all peers
				err := dg.Connect(ctx)
				if err != nil {
					return nil, "", err
				}
			}

			// send the envelope for ordering  调用BroadcastClient发送给orderer进行排序
			if err = cf.BroadcastClient.Send(env); err != nil {
				return proposalResp, "", errors.WithMessage(err, "error sending transaction")
			}

			if dg != nil && ctx != nil {
				// wait for event that contains the txid from all peers
				err = dg.Wait(ctx)
				if err != nil {
					return nil, "", err
				}
			}
		}
	}

	return proposalResp, result, nil
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
					fmt.Printf("txid [%s] committed with status (%s) at %s", dg.TxID, tx.TxValidationCode, dc.Address)
					return
				}
			}
		case *pb.DeliverResponse_Status:
			err = errors.Errorf("deliver completed with status (%s) before txid received", r.Status)
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
		tlsCertHash = util.ComputeSHA256(certificate.Certificate[0])
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

	//  env, err := fprotoutils.CreateSignedEnvelopeWithTLSBinding(
	// 	fcommon.HeaderType_DELIVER_SEEK_INFO, channelID, localmsp.NewSigner(),
	// 	seekInfo, int32(0), uint64(0), tlsCertHash)
	env, err := CreateSignedEnvelopeWithTLSBinding(
		fcommon.HeaderType_DELIVER_SEEK_INFO, channelID, localmsp.NewSigner(),
		seekInfo, int32(0), uint64(0), tlsCertHash)
	if err != nil {
		logger.Errorf("Error signing envelope: %s", err)
		return nil
	}

	return env
}

func CreateSignedEnvelopeWithTLSBinding(txType fcommon.HeaderType, channelID string, signer localmsp.LocalSigner, dataMsg proto.Message, msgVersion int32, epoch uint64, tlsCertHash []byte) (*fcommon.Envelope, error) {
	payloadChannelHeader := MakeChannelHeader(txType, msgVersion, channelID, epoch)
	payloadChannelHeader.TlsCertHash = tlsCertHash
	var err error
	payloadSignatureHeader := &fcommon.SignatureHeader{}

	if signer != nil {
		payloadSignatureHeader, err = signer.NewSignatureHeader()
		if err != nil {
			return nil, err
		}
	}
	fmt.Println(dataMsg)
	data, err := proto.Marshal(dataMsg)
	if err != nil {
		return nil, err
	}

	paylBytes := MarshalOrPanic(&fcommon.Payload{
		Header: MakePayloadHeader(payloadChannelHeader, payloadSignatureHeader),
		Data:   data,
	})

	var sig []byte
	if signer != nil {
		sig, err = signer.Sign(paylBytes)
		if err != nil {
			return nil, err
		}
	}

	return &fcommon.Envelope{Payload: paylBytes, Signature: sig}, nil
}

func MakeChannelHeader(headerType fcommon.HeaderType, version int32, chainID string, epoch uint64) *fcommon.ChannelHeader {
	return &fcommon.ChannelHeader{
		Type:    int32(headerType),
		Version: version,
		// Timestamp: &timestamp.Timestamp{
		// 	Seconds: time.Now().Unix(),
		// 	Nanos:   0,
		// },
		ChannelId: chainID,
		Epoch:     epoch,
	}
}

// MakePayloadHeader creates a Payload Header.
func MakePayloadHeader(ch *fcommon.ChannelHeader, sh *fcommon.SignatureHeader) *fcommon.Header {
	return &fcommon.Header{
		ChannelHeader:   MarshalOrPanic(ch),
		SignatureHeader: MarshalOrPanic(sh),
	}
}

func MarshalOrPanic(pb proto.Message) []byte {
	data, err := proto.Marshal(pb)
	if err != nil {
		panic(err)
	}
	return data
}
