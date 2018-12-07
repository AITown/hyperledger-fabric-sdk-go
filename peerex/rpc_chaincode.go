package peerex

import (
	"hyperledger-fabric-sdk-go/msp"
	"hyperledger-fabric-sdk-go/utils"
)

type Handle interface {
	Invoke(funcName string, args []string) (string, error)
	Query(funcName string, args []string) (string, error)
}

type RPCBuilder struct {
	rPCBuilder
	// Handle
}

func NewRpcBuilder() *RPCBuilder {
	r := new(RPCBuilder)
	r.ChaincodeEnv = new(ChaincodeEnv)
	r.MspEnv = new(msp.MspEnv)
	r.Peers = make([]*PeerEnv, 0)
	r.OrderEnv = new(OrderEnv)
	return r
}

//Invoke 执行交易  方法的参数  格式:args:[]string{"a","b","10"} 代表a給b转10元值 跟方法名要匹配
func (r *RPCBuilder) Invoke(funcName string, args []string) (string, error) {
	if !utils.IsNullOrEmpty(funcName) {
		r.Function = funcName
	}
	return r.rPCBuilder.Invoke(args)
}

//Query 查询  格式: args:[]string{"a"} 代表查询a的值 跟方法名要匹配
func (r *RPCBuilder) Query(funcName string, args []string) (string, error) {
	if !utils.IsNullOrEmpty(funcName) {
		r.Function = funcName
	}
	return r.rPCBuilder.Query(args)
}
