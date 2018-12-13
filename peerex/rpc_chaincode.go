package peerex

import (
	"encoding/json"
	"fmt"
	"hyperledger-fabric-sdk-go/msp"
	"hyperledger-fabric-sdk-go/utils"
	"strconv"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
	futils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

// These are function names from Invoke first parameter
const (
	GetChainInfo       string = "GetChainInfo"
	GetBlockByNumber   string = "GetBlockByNumber"
	GetBlockByHash     string = "GetBlockByHash"
	GetTransactionByID string = "GetTransactionByID"
	GetBlockByTxID     string = "GetBlockByTxID"
	InnerCC            string = "qscc"
)

type Handle interface {
	Invoke(funcName string, args []string) (string, error)
	Query(funcName string, args []string) (string, error)
	GetChainInfo() (string, error)
	GetBlcokHeight() (int64, error)
	GetTransactionByID(tid string) (string, error)
	GetBlockByNumber(h int64) (string, error)
}

type rPCBuilder struct {
	*RPCBuilder
}

func NewRpcBuilder() *RPCBuilder {
	r := new(RPCBuilder)
	r.ChaincodeEnv = new(ChaincodeEnv)
	r.MspEnv = new(msp.MspEnv)
	r.Peers = make([]*PeerEnv, 0)
	r.OrderEnv = new(OrderEnv)
	return r
}

// 该日志 来自fabric_1.2 ，现在是输出到终端。需要添加输出到文件的
var logger = utils.MustGetLogger(logsymbol)

func initLog() {
	l := viper.GetString("logging.level")
	utils.SetModuleLevel("^"+logsymbol, l)
	format := viper.GetString("logging.format")
	utils.SetFormat(format)
}

//InitWithFile  1.2版的viper 没有setfile 方法
func InitWithFile(filename string, configPath ...string) (Handle, error) {
	if err := utils.InitViper(filename, filename, configPath...); err != nil {
		return nil, fmt.Errorf("utils.InitPeerViper faile:%s", err.Error())
	}
	initLog()
	logger.Debug("1.2 fabric load config,path:", viper.ConfigFileUsed())
	rpc := NewRpcBuilder()
	if s := viper.GetString("chaincode"); s != "" {
		rpc.ChaincodeName = s
	}
	if s := viper.GetString("channel"); s != "" {
		rpc.ChannelID = s
	}
	logger.Debug("get node conf ChannelID:", rpc.ChannelID, "chaincode:", rpc.ChaincodeName)
	nodes := viper.GetStringSlice("peers")
	logger.Debug("peers:", nodes)
	if nodes != nil && len(nodes) > 0 {
		for _, node := range nodes {
			nodeCof := getConfig(node)
			rpc.Peers = append(rpc.Peers, &PeerEnv{nodeCof})
		}
	} else {
		return nil, errors.New("没有发现peers节点配置")
	}
	logger.Debug("get orderer conf")
	rpc.OrderEnv = &OrderEnv{
		NodeEnv: getConfig("orderer"),
	}
	logger.Debug("get msp conf")
	rpc.MspConfigPath = viper.GetString("msp.mspConfigPath")
	rpc.MspID = viper.GetString("msp.localMspId")
	rpc.MspType = viper.GetString("msp.localMspType")

	logger.Debug("MspConfigPath", rpc.MspConfigPath)

	err := InitCrypto(rpc.MspEnv)
	if err != nil {
		return nil, err
	}
	return &rPCBuilder{
		rpc,
	}, nil
}

func getConfig(pre string) *NodeEnv {
	logger.Debug("get node conf pre", pre)
	node := new(NodeEnv)
	node.Address = viper.GetString(pre + ".address")
	node.HostnameOverride = viper.GetString(pre + ".serverhostoverride")
	node.TLS = viper.GetBool(pre + ".tls")
	node.RootCertFile = viper.GetString(pre + ".rootcert")
	node.ConnTimeout = viper.GetDuration(pre + ".conntimeout")
	logger.Debug(node, "---", node.Address, node.TLS, node.RootCertFile, node.HostnameOverride)
	return node
}

//Invoke 执行交易  方法的参数  格式:args:[]string{"a","b","10"} 代表a給b转10元值 跟方法名要匹配
func (r *rPCBuilder) Invoke(funcName string, args []string) (string, error) {
	if !utils.IsNullOrEmpty(funcName) {
		r.Function = funcName
	}
	return r.RPCBuilder.Invoke(args)
}

//Query 查询  格式: args:[]string{"a"} 代表查询a的值 跟方法名要匹配
func (r *rPCBuilder) Query(funcName string, args []string) (string, error) {
	if !utils.IsNullOrEmpty(funcName) {
		r.Function = funcName
	}

	res, err := r.RPCBuilder.Query(args)
	if err != nil {
		return "", err
	}
	return string(res.Payload), nil
}

type BlockInfo struct {
	Height            uint64 `json:"height,omitempty"`
	CurrentBlockHash  string `json:"currentBlockHash,omitempty"`
	PreviousBlockHash string `json:"previousBlockHash,omitempty"`
}

//GetChainInfo
func (r *rPCBuilder) GetChainInfo() (string, error) {
	chainName := r.ChaincodeName
	defer func() { r.ChaincodeName = chainName }()
	r.Function = GetChainInfo
	r.ChaincodeName = InnerCC
	res, err := r.RPCBuilder.Query([]string{r.ChannelID})
	if err != nil {
		return "", err
	}
	bi := &common.BlockchainInfo{}
	proto.Unmarshal(res.Payload, bi)

	info := BlockInfo{
		bi.Height,
		fmt.Sprintf("%x", bi.CurrentBlockHash),
		fmt.Sprintf("%x", bi.PreviousBlockHash),
	}
	b, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	fmt.Println("GetChainInfo", string(b))
	return string(b), nil
}

func (r *rPCBuilder) GetBlcokHeight() (int64, error) {
	chainName := r.ChaincodeName
	defer func() { r.ChaincodeName = chainName }()
	r.Function = GetChainInfo
	r.ChaincodeName = InnerCC
	res, err := r.RPCBuilder.Query([]string{r.ChannelID})
	if err != nil {
		return 0, err
	}
	bi := &common.BlockchainInfo{}
	proto.Unmarshal(res.Payload, bi)

	return int64(bi.Height), nil
}

type ChainTransaction struct {
	Height      int64    `json:"height"`
	TxID        string   `json:"txID"`
	Chaincode   string   `json:"name"`
	Method      string   `json:"func"`
	CreatedFlag bool     `json:"createdFlag"`
	TxArgs      [][]byte `json:"-"`
}

//GetTransactionByID
func (r *rPCBuilder) GetTransactionByID(tid string) (string, error) {
	chainName := r.ChaincodeName
	defer func() { r.ChaincodeName = chainName }()
	r.Function = GetTransactionByID
	r.ChaincodeName = InnerCC
	res, err := r.RPCBuilder.Query([]string{r.ChannelID, tid})
	if err != nil {
		return "", err
	}

	trans := &pb.ProcessedTransaction{}
	err = proto.Unmarshal(res.Payload, trans)
	if err != nil {
		return "", err
	}

	tx, err := envelopeToTrasaction(trans.TransactionEnvelope)

	//tx.TxID
	if err != nil {
		return "", err
	}
	blk, err := r.GetBlockByTxID(tx.TxID)

	if err == nil {
		tx.Height = int64(blk.Header.Number)
	}

	b, err := json.Marshal(tx)
	if err != nil {
		return "", err
	}
	fmt.Println("GetTransactionByID", string(b))
	return string(b), nil
}

func envelopeToTrasaction(env *common.Envelope) (*ChainTransaction, error) {
	ta := &ChainTransaction{}
	//	//====Transaction====== []
	// Height                  int64 `json:",string"`
	// TxID, Chaincode, Method string
	// CreatedFlag             bool
	// TxArgs                  [][]byte `json:"-"`

	var err error
	if env == nil {
		return ta, errors.New("common.Envelope is nil")
	}
	payl := &common.Payload{}
	err = proto.Unmarshal(env.Payload, payl)
	if err != nil {
		return nil, err
	}
	tx := &pb.Transaction{}
	err = proto.Unmarshal(payl.Data, tx)
	if err != nil {
		return nil, err
	}

	taa := &pb.TransactionAction{}
	taa = tx.Actions[0]

	cap := &pb.ChaincodeActionPayload{}
	err = proto.Unmarshal(taa.Payload, cap)
	if err != nil {
		return nil, err
	}

	pPayl := &pb.ChaincodeProposalPayload{}
	proto.Unmarshal(cap.ChaincodeProposalPayload, pPayl)

	prop := &pb.Proposal{}
	pay, err := proto.Marshal(pPayl)
	if err != nil {
		return nil, err
	}

	prop.Payload = pay
	h, err := proto.Marshal(payl.Header)
	if err != nil {
		return nil, err
	}
	prop.Header = h

	invocation := &pb.ChaincodeInvocationSpec{}
	err = proto.Unmarshal(pPayl.Input, invocation)
	if err != nil {
		return nil, err
	}

	spec := invocation.ChaincodeSpec

	// hdr := &common.Header{}
	// hdr = payl.Header
	channelHeader := &common.ChannelHeader{}
	proto.Unmarshal(payl.Header.ChannelHeader, channelHeader)

	ta.TxID = channelHeader.TxId
	ta.TxArgs = spec.GetInput().GetArgs()[1:]
	ta.Chaincode = spec.GetChaincodeId().GetName()
	ta.Method = string(spec.GetInput().GetArgs()[0])
	ta.CreatedFlag = channelHeader.GetType() == int32(common.HeaderType_ENDORSER_TRANSACTION)
	return ta, nil
}

func (r *rPCBuilder) GetBlockByTxID(txid string) (*common.Block, error) {
	chainName := r.ChaincodeName
	defer func() { r.ChaincodeName = chainName }()
	r.Function = GetBlockByTxID
	r.ChaincodeName = InnerCC

	res, err := r.RPCBuilder.Query([]string{r.ChannelID, txid})
	if err != nil {
		return nil, err
	}
	blk := &common.Block{}
	err = proto.Unmarshal(res.Payload, blk)
	if err != nil {
		return nil, err
	}
	return blk, nil
}

func (r *rPCBuilder) GetBlockByNumber(h int64) (string, error) {
	chainName := r.ChaincodeName
	defer func() { r.ChaincodeName = chainName }()
	r.Function = GetBlockByNumber
	r.ChaincodeName = InnerCC
	height := strconv.FormatInt(h, 10)
	res, err := r.RPCBuilder.Query([]string{r.ChannelID, height})
	if err != nil {
		return "", err
	}
	blk := &common.Block{}
	err = proto.Unmarshal(res.Payload, blk)
	if err != nil {
		return "", err
	}
	outblk := new(ChainBlock)
	//转化-=----
	outblk.Hash = fmt.Sprintf("%x", blk.Header.DataHash)
	fmt.Println("blk.Header.number:", blk.Header.Number)
	outblk.Height = h
	chaincodeEvents := getChainCodeEvents(blk)
	for _, et := range chaincodeEvents {
		outblk.TxEvents = append(outblk.TxEvents, eventConvert(et))
	}

	//此处应该遍历block.Data.Data?
	fmt.Println("blk.Data.Data", len(blk.Data.Data))
	for _, data := range blk.Data.Data {
		// ret := &client.ChainTransaction{}
		envelope := &common.Envelope{}
		if err = proto.Unmarshal(data, envelope); err != nil {
			return "", fmt.Errorf("error reconstructing envelope(%s)", err)
		}
		transaction, err := envelopeToTrasaction(envelope)
		if err != nil {
			continue
		}
		ret := transaction
		ret.Height = h
		outblk.Transactions = append(outblk.Transactions, ret)
	}
	b, _ := json.Marshal(outblk)
	return string(b), nil
}

type ChainBlock struct {
	Height       int64               `json:"height"`
	Hash         string              `json:"hash"`
	TimeStamp    string              `json:"time"`
	Transactions []*ChainTransaction `json:"transactions"`
	TxEvents     []*ChainTxEvents    `json:"chainTxEvents"`
}

type ChainTxEvents struct {
	Status    int    `json"status"`
	Payload   []byte `json:"-"`
	TxID      string `json:"txID"`
	Chaincode string `json:"ccName"`
	Name      string `json:"eventName"`
}

// getChainCodeEvents parses block events for chaincode events associated with individual transactions
func getChainCodeEvents(block *common.Block) []*pb.ChaincodeEvent {
	if block == nil || block.Data == nil || block.Data.Data == nil || len(block.Data.Data) == 0 {
		return nil
	}
	// var err error
	events := make([]*pb.ChaincodeEvent, 0)
	// env := &common.Envelope{}
	//此处应该遍历block.Data.Data？
	for _, data := range block.Data.Data {
		event, err := getChainCodeEventsByByte(data)
		if err != nil {
			continue
		}
		events = append(events, event)
	}
	return events

}

func getChainCodeEventsByByte(data []byte) (*pb.ChaincodeEvent, error) {
	// env := &common.Envelope{}
	// if err := proto.Unmarshal(data, env); err != nil {
	// 	return nil, fmt.Errorf("error reconstructing envelope(%s)", err)
	// }

	env, err := futils.GetEnvelopeFromBlock(data)
	if err != nil {
		return nil, fmt.Errorf("error reconstructing envelope(%s)", err)
	}
	// get the payload from the envelope
	payload, err := futils.GetPayload(env)
	if err != nil {
		return nil, fmt.Errorf("Could not extract payload from envelope, err %s", err)
	}

	chdr, err := futils.UnmarshalChannelHeader(payload.Header.ChannelHeader)
	if err != nil {
		return nil, fmt.Errorf("Could not extract channel header from envelope, err %s", err)
	}

	if common.HeaderType(chdr.Type) == common.HeaderType_ENDORSER_TRANSACTION {

		tx, err := futils.GetTransaction(payload.Data)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshalling transaction payload for block event: %s", err)
		}
		//此处应该遍历tx.Actions？
		chaincodeActionPayload, err := futils.GetChaincodeActionPayload(tx.Actions[0].Payload)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshalling transaction action payload for block event: %s", err)
		}
		propRespPayload, err := futils.GetProposalResponsePayload(chaincodeActionPayload.Action.ProposalResponsePayload)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshalling proposal response payload for block event: %s", err)
		}

		caPayload, err := futils.GetChaincodeAction(propRespPayload.Extension)
		if err != nil {
			return nil, fmt.Errorf("Error unmarshalling chaincode action for block event: %s", err)
		}
		ccEvent, err := futils.GetChaincodeEvents(caPayload.Events)
		if ccEvent != nil {
			return ccEvent, nil
		}

	}
	return nil, errors.New("no HeaderType_ENDORSER_TRANSACTION type ")
}

func eventConvert(event *pb.ChaincodeEvent) *ChainTxEvents {
	if event == nil {
		return nil
	}
	clientEvent := &ChainTxEvents{}
	clientEvent.Chaincode = event.ChaincodeId
	clientEvent.Name = event.EventName
	clientEvent.Payload = event.Payload
	clientEvent.TxID = event.TxId
	return clientEvent
}
