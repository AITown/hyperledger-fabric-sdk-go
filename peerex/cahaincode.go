package peerex

import (
	"hyperledger-fabric-sdk-go/peerex/utils"

	pb "github.com/hyperledger/fabric/protos/peer"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	query     = "query"
	invoke    = "invoke"
	logsymbol = "cc"
)

// 该日志 来自fabric_1.2 ，现在是输出到终端。需要添加输出到文件的
var logger = utils.MustGetLogger(logsymbol)

var rpcCommonDate *rPCBuilder

func initLog() {
	l := viper.GetString("logging.level")
	utils.SetModuleLevel("^"+logsymbol, l)
	format := viper.GetString("logging.format")
	utils.SetFormat(format)
}

//Query 查询  格式: args:[]string{"a"} 代表查询a的值 跟方法名要匹配
func (r *rPCBuilder) Query(args []string) (string, error) {
	initLog()
	r.args = args
	err := r.Verify(false)
	if err != nil {
		return "", err
	}

	rpcCommonDate = r
	r.InitConfig()
	err = InitCrypto(r.MspEnv)
	if err != nil {
		return "", err
	}

	logger.Debug("========InitFactory start:============")
	cf, err := r.InitFactory(false, true, false)
	if err != nil {
		return "", err
	}

	return r.ChaincodeEnv.Query(cf, args)
}

func (r *rPCBuilder) Invoke(args []string) (string, error) {
	initLog()
	r.args = args
	if err := r.Verify(true); err != nil {
		return "", err
	}
	rpcCommonDate = r
	r.InitConfig()
	InitCrypto(r.MspEnv)
	cf, err := r.InitFactory(true, true, true)
	if err != nil {
		return "", err
	}

	defer cf.BroadcastClient.Close()

	return r.ChaincodeEnv.Invoke(cf, args)
}

func (cc *ChaincodeEnv) Query(cf *ChaincodeFactory, args []string) (string, error) {
	pb, _, err := cc.handle(cf, false, args)
	if err != nil {
		return "", nil
	}
	return string(pb.Response.Payload), nil
}

func (cc *ChaincodeEnv) Invoke(cf *ChaincodeFactory, args []string) (string, error) {
	_, txid, err := cc.handle(cf, true, args)
	if err != nil {
		return "", nil
	}
	return txid, nil
}

func (cc *ChaincodeEnv) handle(cf *ChaincodeFactory, invoke bool, args []string) (*pb.ProposalResponse, string, error) {

	// call with empty txid to ensure production code generates a txid.
	// otherwise, tests can explicitly set their own txid
	spec := cc.getChaincodeSpec(args)

	//proposalResp, _, err := ChaincodeInvokeOrQuery(spec, rpcCommonDate.ChannelID, txID, false, cf.Signer, cf.Certificate, cf.EndorserClients, cf.DeliverClients, cf.BroadcastClient)
	proposalResp, txid, err := cf.ChaincodeInvokeOrQuery(spec, cc.ChannelID, "", invoke)
	if err != nil {
		return nil, "", errors.Errorf("%s - proposal response: %v", err, proposalResp)
	}

	if proposalResp == nil {
		return nil, "", errors.New("error during query: received nil proposal response")
	}
	if proposalResp.Endorsement == nil {
		return nil, "", errors.Errorf("endorsement failure during query. response: %v", proposalResp.Response)
	}

	return proposalResp, txid, nil
}
