package peerex

import (
	"hyperledger-fabric-sdk-go/peerex/utils/flogging"
)

const (
	query     = "query"
	invoke    = "invoke"
	logsymbol = "chaincodeEX"
)

// 该日志 来自fabric_1.2 ，现在是输出到终端。需要添加输出到文件的
var logger = flogging.MustGetLogger(logsymbol)

var rpcCommonDate *RPCBuilder

//Invoke 执行交易  方法的参数  格式:args:[]string{"a","b","10"} 代表a給b转10元值 跟方法名要匹配
func (r *RPCBuilder) Invoke(args []string) (string, error) {
	r.args = args
	if err := checkChaincodeCmdParams(r); err != nil {
		return "", err
	}
	rpcCommonDate = r
	initConfig(r)
	initCrypto()
	cf, err := InitFactory(invoke, true, true)
	if err != nil {
		return "", err
	}

	defer cf.BroadcastClient.Close()

	return chaincodeInvokeOrQuery(args, true, cf)

}

//Query 查询  格式: args:[]string{"a"} 代表查询a的值 跟方法名要匹配
func (r *RPCBuilder) Query(args []string) (string, error) {
	r.args = args
	if err := checkChaincodeCmdParams(r); err != nil {
		return "", err
	}

	rpcCommonDate = r
	initConfig(r)
	initCrypto()

	logger.Info("InitFactory start:============")
	cf, err := InitFactory(query, true, false)
	if err != nil {
		return "", err
	}

	return chaincodeInvokeOrQuery(args, false, cf)
}
