package peerex

import (
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/hyperledger/fabric/common/localmsp"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	"github.com/hyperledger/fabric/msp"

	"hyperledger-fabric-sdk-go/peerex/common"

	fcommon "github.com/hyperledger/fabric/peer/common"
	"github.com/hyperledger/fabric/peer/common/api"
	pcommon "github.com/hyperledger/fabric/protos/common"
	ab "github.com/hyperledger/fabric/protos/orderer"
	pb "github.com/hyperledger/fabric/protos/peer"
	putils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	escc         = "escc"
	vscc         = "vscc"
	localMspType = "bccsp"
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

//checkChaincodeCmdParams 检查参数正确性 没有的构建默认值
func checkChaincodeCmdParams(r *RPCBuilder) error {
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
			logger.Info("Using default Function:", query)
		} else {
			r.Function = invoke
			logger.Info("Using default Function:", invoke)
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
	if r.PeerLocalMspType == "" {
		r.PeerLocalMspType = localMspType
	}

	//add by gjf
	if r.WaitForEvent == true && r.WaitForEventTimeout == time.Duration(0) {
		r.WaitForEventTimeout = time.Second * 30
	}

	if r.OrdererTLS != "" {
		tls := strings.ToLower(strings.Trim(r.OrdererTLS, " "))
		b, e := strconv.ParseBool(tls)

		if e != nil {
			logger.Warning("OrdererTLS 解析失败，将使用配置文件orderer.tls.enable的值")
			r.orderertls = viper.GetBool(ordererTLS)
		} else {
			r.orderertls = b
		}
	}
	if r.OrdererTLSClientAuthRequired != "" {
		tls := strings.ToLower(strings.Trim(r.OrdererTLSClientAuthRequired, " "))
		b, e := strconv.ParseBool(tls)

		if e != nil {
			logger.Warning("OrdererTLSClientAuthRequired 解析失败，将使用配置文件orderer.tls.clientAuthRequired")
			r.orderertlsclientauth = viper.GetBool(ordererTLSClientAuthRequired)
		} else {
			r.orderertlsclientauth = b
		}
	}
	if r.PeerTLS != "" {
		tls := strings.ToLower(strings.Trim(r.PeerTLS, " "))
		b, e := strconv.ParseBool(tls)

		if e != nil {
			logger.Warning("PeerTLS 解析失败，将使用配置文件peer.tls.enable的值")
			r.peertls = viper.GetBool(peerTLSEnabled)
		} else {
			r.peertls = b
		}
	}
	if r.PeerTLSClientAuthRequired != "" {
		tls := strings.ToLower(strings.Trim(r.PeerTLSClientAuthRequired, " "))
		b, e := strconv.ParseBool(tls)

		if e != nil {
			logger.Warning("PeerTLS 解析失败，将使用配置文件peer.tls.clientAuthRequired的值")
			r.peertlsclientauth = viper.GetBool(peerTLSClientAuthRequired)
		} else {
			r.peertlsclientauth = b
		}
		fmt.Println("r.orderertlsclientauth", r.peertlsclientauth)
	}

	if len(r.PeerAddresses) == 0 {
		logger.Info("PeerAddresses is nil")
		r.PeerAddresses = make([]string, 1)
	}

	logger.Debug("检查参数正确性=======down")
	return nil
}

func initCrypto() {
	var mspMgrConfigDir = common.GetPath(peerMspConfigPath)
	var mspID = viper.GetString(peerLocalMspID)
	var mspType = viper.GetString(peerLocalMspType)

	if mspType == "" {
		mspType = msp.ProviderTypeToString(msp.FABRIC)
	}

	fmt.Println("init使用的路径: ", viper.ConfigFileUsed())
	fmt.Printf("get config mspMgrConfigDir:%s==mspID:%s==mspType:%s \n", mspMgrConfigDir, mspID, mspType)

	err := common.InitCrypto(mspMgrConfigDir, mspID, mspType)
	if err != nil {
		// Handle errors reading the config file
		logger.Errorf("Cannot run peer because %s", err.Error())
		os.Exit(1)
	}

}

//初始化配置变量
func initConfig(r *RPCBuilder) {
	fmt.Println("viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))

	//os.Setenv("CORE_PEER_ADDRESS", peerAddress)
	//os.Setenv("CORE_PEER_TLS_ROOTCERT_FILE", peerTLSRootCertFile)
	//os.Setenv("CORE_PEER_TLS_SERVERHOSTOVERRIDE", peerTLSServerhostOverride)

	//peer
	//peerAddress  peerTLSRootCertFile peerTLSServerhostOverride 在invoke时不做变化
	connttime := viper.GetDuration(peerClientconntimeout)
	if r.PeerClientConnTimeout != connttime {
		viper.Set(peerClientconntimeout, r.PeerClientConnTimeout.String())
	}
	if r.PeerTLS != "" {
		viper.Set(peerTLSEnabled, r.peertls)
	}
	if r.PeerTLSClientAuthRequired != "" {
		viper.Set(peerTLSClientAuthRequired, r.peertlsclientauth)
	}
	if r.PeerTLSCertFile != "" {
		viper.Set(peerTLSCertFile, r.PeerTLSCertFile)
	}
	if r.PeerTLSKeyFile != "" {
		viper.Set(peerTLSKeyFile, r.PeerTLSKeyFile)
	}
	if r.PeerTLSClientCertFile != "" {
		viper.Set(peerTLSClientCertFile, r.PeerTLSClientCertFile)
	}
	if r.PeerTLSClientKeyFile != "" {
		viper.Set(peerTLSClientKeyFile, r.PeerTLSClientKeyFile)
	}
	//msp
	if r.PeerLocalMspID != "" {
		viper.Set(peerLocalMspID, r.PeerLocalMspID)
	}
	if r.PeerMspConfigPath != "" {
		viper.Set(peerMspConfigPath, r.PeerMspConfigPath)
	}
	if r.PeerLocalMspType != "" {
		viper.Set(peerLocalMspType, r.PeerLocalMspType)
	}

	//order
	connttime = viper.GetDuration(ordererConnTimeout)
	if r.OrdererConnTimeout != connttime {
		viper.Set(ordererConnTimeout, r.OrdererConnTimeout)
	}
	if r.OrdererTLS != "" {
		viper.Set(ordererTLS, r.orderertls)
	}
	if r.OrdererTLSClientAuthRequired != "" {
		viper.Set(ordererTLSClientAuthRequired, r.orderertlsclientauth)
	}
	if r.OrdererAddress != "" {
		viper.Set(ordererEndpoint, r.OrdererAddress)
	}
	if r.OrdererTLSHostnameOverride != "" {
		viper.Set(ordererTLSHostnameOverride, r.OrdererTLSHostnameOverride)
	}
	if r.OrdererTLSClientCertFile != "" {
		os.Setenv(ordererTLSClientCertFile, r.OrdererTLSClientCertFile)
	}
	if r.OrdererTLSClientKeyFile != "" {
		os.Setenv(ordererTLSClientKeyFile, r.OrdererTLSClientKeyFile)
	}
	if r.OrdererTLSRootCertFile != "" {
		os.Setenv(ordererTLSRootCertFile, r.OrdererTLSRootCertFile)
	}

}

func validatePeerConnectionParameters(cmdName string, tlsRootCertFiles, peerAddresses, override []string) error {
	// currently only support multiple peer addresses for invoke 当前只有invoke 支持多节点
	if cmdName != invoke && len(peerAddresses) > 1 {
		return errors.Errorf("'%s' command can only be executed against one peer. received %d", cmdName, len(peerAddresses))
	}

	if len(tlsRootCertFiles) > len(peerAddresses) {
		logger.Warningf("received more TLS root cert files (%d) than peer addresses (%d)", len(tlsRootCertFiles), len(peerAddresses))
	}
	if len(override) < len(peerAddresses) {
		return errors.Errorf("hostnameoverride的个数小于peeraddress的个数")
	}

	if viper.GetBool("peer.tls.enabled") {
		if len(tlsRootCertFiles) != len(peerAddresses) || len(tlsRootCertFiles) != len(override) {
			return errors.Errorf("number of peer addresses (%d) does not match the number of TLS root cert files (%d)", len(peerAddresses), len(tlsRootCertFiles))
		}
	} else {
		tlsRootCertFiles = nil
	}

	return nil
}

//InitFactory 初始化chaincode命令工厂
func InitFactory(cmdName string, isEndorserRequired, isOrdererRequired bool) (*ChaincodeCmdFactory, error) {
	var (
		err                  error
		endorserClients      []pb.EndorserClient
		deliverClients       []api.PeerDeliverClient
		tlsRootCertFiles     = rpcCommonDate.PeerTLSRootCertFile
		peerAddresses        = rpcCommonDate.PeerAddresses
		peerhostoverrides    = rpcCommonDate.PeerTLSHostnameOverride
		ordererAddresses     = rpcCommonDate.OrdererAddress
		ordererhostoverrides = rpcCommonDate.OrdererTLSHostnameOverride
	)
	//背书请求 如果需要跟endorser通信，那么创建endorserClient，参见peerclient.go的NewPeerClientFromEnv函数。
	if isEndorserRequired {
		if err = validatePeerConnectionParameters(cmdName, tlsRootCertFiles, peerAddresses, peerhostoverrides); err != nil {
			return nil, errors.WithMessage(err, "error validating peer connection parameters")
		}
		//多个peer节点
		for i, address := range peerAddresses {
			var tlsRootCertFile string
			if tlsRootCertFiles != nil {
				tlsRootCertFile = tlsRootCertFiles[i]
			}
			var override string
			if peerhostoverrides != nil {
				override = peerhostoverrides[i]
			}
			//error getting endorser client for query: endorser client failed to connect to
			//path: failed to create new connection: context deadline exceeded
			fmt.Println("common.GetEndorserClientFnc :override:=", override)
			endorserClient, err := common.GetEndorserClientFnc(address, tlsRootCertFile, override)
			if err != nil {
				return nil, errors.WithMessage(err, fmt.Sprintf("error getting endorser client for %s", cmdName))
			}

			endorserClients = append(endorserClients, endorserClient)
			deliverClient, err := common.GetPeerDeliverClientFnc(address, tlsRootCertFile, override)
			if err != nil {
				return nil, errors.WithMessage(err, fmt.Sprintf("error getting deliver client for %s", cmdName))
			}
			deliverClients = append(deliverClients, deliverClient)
		}

		if len(endorserClients) == 0 {
			return nil, errors.New("no endorser clients retrieved - this might indicate a bug")
		}
	}
	certificate, err := common.GetCertificateFnc()
	if err != nil {
		return nil, errors.WithMessage(err, "error getting client cerificate")
	}

	signer, err := common.GetDefaultSignerFnc()
	if err != nil {
		return nil, errors.WithMessage(err, "error getting default signer")
	}

	var broadcastClient fcommon.BroadcastClient
	// 如果需要跟orderer通信，那么创建跟orderer交互的BroadcastClient。
	// 如果配置没有指定orderer的地址，那么使用GetOrdererEndpointOfChainFnc函数获取所有orderer的地址，取第一个作为通信orderer，调用GetBroadcastClientFnc函数获取BroadcastClient，
	// 如果指定了orderer地址，那么直接调用GetBroadcastClientFnc获取BroadcastClient。

	if isOrdererRequired {
		if len(ordererAddresses) == 0 {
			if len(endorserClients) == 0 {
				return nil, errors.New("orderer is required, but no ordering endpoint or endorser client supplied")
			}

			endorserClient := endorserClients[0]
			orderingEndpoints, err := common.GetOrdererEndpointOfChainFnc(rpcCommonDate.ChannelID, signer, endorserClient)
			if err != nil {
				return nil, errors.WithMessage(err, fmt.Sprintf("error getting channel (%s) orderer endpoint", rpcCommonDate.ChannelID))
			}
			if len(orderingEndpoints) == 0 {
				return nil, errors.Errorf("no orderer endpoints retrieved for channel %s", rpcCommonDate.ChannelID)
			}
			logger.Infof("Retrieved channel (%s) orderer endpoint: %s", rpcCommonDate.ChannelID, orderingEndpoints[0])
			// override viper env
			viper.Set("orderer.address", orderingEndpoints[0])
		}
		fmt.Println("----开始根据环境变量构建:GetBroadcastClientFnc")
		broadcastClient, err = common.GetBroadcastClientFnc(ordererAddresses, ordererhostoverrides)

		if err != nil {
			return nil, errors.WithMessage(err, "error ==getting broadcast client")
		}
	}

	// 根据上面获得信息组装ChaincodeCmdFactory返回
	return &ChaincodeCmdFactory{
		EndorserClients: endorserClients,
		DeliverClients:  deliverClients,
		Signer:          signer,
		BroadcastClient: broadcastClient,
		Certificate:     certificate,
	}, nil
}

// getChaincodeSpec get chaincode spec from the  pramameters
func getChaincodeSpec(args []string) (*pb.ChaincodeSpec, error) {
	spec := &pb.ChaincodeSpec{}
	funcname := rpcCommonDate.Function
	input := &pb.ChaincodeInput{}
	input.Args = make([][]byte, len(args)+1)
	if len(funcname) == 0 {
		return nil, errors.New("方法名为空")
	}
	input.Args[0] = []byte(funcname)
	for i, x := range args {
		input.Args[i+1] = []byte(x)
	}

	fmt.Println("ChaincodeSpec input :", input, " funcname:", funcname)
	var golang = pb.ChaincodeSpec_Type_name[1]
	spec = &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[golang]),
		ChaincodeId: &pb.ChaincodeID{Name: rpcCommonDate.ChaincodeName, Version: rpcCommonDate.ChaincodeVersion},
		Input:       input,
	}
	return spec, nil
}

func chaincodeInvokeOrQuery(args []string, invoke bool, cf *ChaincodeCmdFactory) (string, error) {
	var str string
	spec, err := getChaincodeSpec(args)
	if err != nil {
		return "", err
	}

	// call with empty txid to ensure production code generates a txid.
	// otherwise, tests can explicitly set their own txid
	txID := ""
	proposalResp, txid, err := ChaincodeInvokeOrQuery(spec, rpcCommonDate.ChannelID, txID, invoke, cf.Signer, cf.Certificate, cf.EndorserClients, cf.DeliverClients, cf.BroadcastClient)
	if err != nil {
		return "", errors.Errorf("%s - proposal response: %v", err, proposalResp)
	}

	if invoke {
		logger.Debugf("ESCC invoke result: %v", proposalResp)
		pRespPayload, err := putils.GetProposalResponsePayload(proposalResp.Payload)
		if err != nil {
			return "", errors.WithMessage(err, "error while unmarshaling proposal response payload")
		}
		ca, err := putils.GetChaincodeAction(pRespPayload.Extension)
		if err != nil {
			return "", errors.WithMessage(err, "error while unmarshaling chaincode action")
		}
		if proposalResp.Endorsement == nil {
			return "", errors.Errorf("endorsement failure during invoke. chaincode result: %v", ca.Response)
		}
		logger.Infof("Chaincode invoke successful. result: %v", ca.Response)
		str = txid
	} else {
		if proposalResp == nil {
			return "", errors.New("error during query: received nil proposal response")
		}
		if proposalResp.Endorsement == nil {
			return "", errors.Errorf("endorsement failure during query. response: %v", proposalResp.Response)
		}
		str = string(proposalResp.Response.Payload)

	}
	return str, nil
}

// ChaincodeInvokeOrQuery invokes or queries the chaincode. If successful, the
// INVOKE form prints the ProposalResponse to STDOUT, and the QUERY form prints
// the query result on STDOUT. A command-line flag (-r, --raw) determines
// whether the query result is output as raw bytes, or as a printable string.
// The printable form is optionally (-x, --hex) a hexadecimal representation
// of the query response. If the query response is NIL, nothing is output.
//
// NOTE - Query will likely go away as all interactions with the endorser are
// Proposal and ProposalResponses
func ChaincodeInvokeOrQuery(spec *pb.ChaincodeSpec, cID string, txID string, invoke bool,
	signer msp.SigningIdentity, certificate tls.Certificate,
	endorserClients []pb.EndorserClient, deliverClients []api.PeerDeliverClient, bc fcommon.BroadcastClient,
) (*pb.ProposalResponse, string, error) {
	var (
		responses []*pb.ProposalResponse
		result    string
	)

	// Build the ChaincodeInvocationSpec message 创建chaincode执行描述结构，创建proposal
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	creator, err := signer.Serialize()
	if err != nil {
		return nil, "", errors.WithMessage(err, fmt.Sprintf("error serializing identity for %s", signer.GetIdentifier()))
	}

	funcName := "invoke"
	if !invoke {
		funcName = "query"
	}

	// extract the transient field if it exists
	var tMap map[string][]byte
	// if transient != "" {
	// 	if err := json.Unmarshal([]byte(transient), &tMap); err != nil {
	// 		return nil, errors.Wrap(err, "error parsing transient string")
	// 	}
	// }

	prop, txid, err := putils.CreateChaincodeProposalWithTxIDAndTransient(pcommon.HeaderType_ENDORSER_TRANSACTION, cID, invocation, creator, txID, tMap)
	fmt.Println(" ChaincodeInvokeOrQuery putils.CreateChaincodeProposalWithTxIDAndTransient", txid)
	if err != nil {
		return nil, "", errors.WithMessage(err, fmt.Sprintf("error creating proposal for %s", funcName))
	}
	result = txid
	//对proposal签名
	signedProp, err := putils.GetSignedProposal(prop, signer)

	if err != nil {
		return nil, "", errors.WithMessage(err, fmt.Sprintf("error creating signed proposal for %s", funcName))
	}
	fmt.Println("ChaincodeInvokeOrQuery putils.GetSignedProposal==== success")
	for _, endorser := range endorserClients {
		//使用grpc调用endorserClient.ProcessProposal，触发endorer执行proposal
		proposalResp, err := endorser.ProcessProposal(context.Background(), signedProp)
		if err != nil {
			return nil, "", errors.WithMessage(err, fmt.Sprintf("error endorsing %s", funcName))
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
			if proposalResp.Response.Status >= shim.ERRORTHRESHOLD {
				return proposalResp, "", nil
			}
			// assemble a signed transaction (it's an Envelope message) 对交易签名CreateSignedTx
			env, err := putils.CreateSignedTx(prop, signer, responses...)
			if err != nil {
				return proposalResp, "", errors.WithMessage(err, "could not assemble transaction")
			}
			fmt.Println("ChaincodeInvokeOrQuery putils.CreateSignedTx 成功")

			var dg *deliverGroup
			var ctx context.Context
			if rpcCommonDate.WaitForEvent {
				var cancelFunc context.CancelFunc
				ctx, cancelFunc = context.WithTimeout(context.Background(), rpcCommonDate.WaitForEventTimeout)
				defer cancelFunc()

				dg = newDeliverGroup(deliverClients, rpcCommonDate.PeerAddresses, certificate, rpcCommonDate.ChannelID, txid)
				fmt.Println("ChaincodeInvokeOrQuery newDeliverGroup 成功")

				// connect to deliver service on all peers
				err := dg.Connect(ctx)
				if err != nil {
					return nil, "", err
				}
			}

			// send the envelope for ordering  调用BroadcastClient发送给orderer进行排序
			if err = bc.Send(env); err != nil {
				return proposalResp, "", errors.WithMessage(err, fmt.Sprintf("error sending transaction for %s", funcName))
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

func createDeliverEnvelope(channelID string, certificate tls.Certificate) *pcommon.Envelope {
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

	env, err := putils.CreateSignedEnvelopeWithTLSBinding(
		pcommon.HeaderType_DELIVER_SEEK_INFO, channelID, localmsp.NewSigner(),
		seekInfo, int32(0), uint64(0), tlsCertHash)
	if err != nil {
		logger.Errorf("Error signing envelope: %s", err)
		fmt.Printf("Error signing envelope: %s", err)
		return nil
	}

	return env
}
