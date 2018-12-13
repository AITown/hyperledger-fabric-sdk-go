package main

import (
	"fmt"
	"hyperledger-fabric-sdk-go/peerex"
	"os"
	"path/filepath"
	"time"
)

const (
	//baseAddr = "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/"
	baseAddr    = "/home/gjf/hyperledger-fabric/fabric-samples/first-network/crypto-config/"
	peerAddress = "127.0.0.1:7051"
	//peerAddress                     = "peer0.org1.example.com:7051"
	peerTLSRootCertFile             = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
	peerClientconntimeout           = "30s"
	peerTLSEnabled                  = true
	peerTLSClientAuthRequired       = true
	peerTLSClientKeyFile            = ""
	peerTLSClientCertFile           = ""
	peerLocalMspID                  = "Org1MSP"
	peerTLSCertFile                 = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt"
	peerTLSKeyFile                  = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key"
	peerMspConfigPath               = baseAddr + "peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
	peerBccspSwFileKeyStoreKeyStore = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/keystore"
	peerTLSServerhostOverride       = "peer0.org1.example.com"

	//peerAddress1         = "peer0.org2.example.com:7051"
	peerAddress1               = "0.0.0.0:9051"
	peerTLSServerhostOverride1 = "peer0.org2.example.com"
	peerTLSRootCertFile1       = baseAddr + "peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
	peerTLSCertFile1           = baseAddr + "peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/server.crt"
	peerTLSKeyFile1            = baseAddr + "peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/server.key"

	//order 配置
	ordererEndpoint = "0.0.0.0:7050"
	//ordererEndpoint              = "orderer.example.com:7050"
	ordererTLS                   = true
	ordererConnTimeout           = 3 * time.Second
	ordererTLSClientAuthRequired = true
	ordererTLSRootCertFile       = baseAddr + "ordererOrganizations/example.com/orderers/orderer.example.com/tls/ca.crt"
	ordererTLSCertFile           = baseAddr + "ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.crt"
	ordererTLSKeyFile            = baseAddr + "ordererOrganizations/example.com/orderers/orderer.example.com/tls/server.key"
	ordererTLSClientKeyFile      = ""
	ordererTLSClientCertFile     = ""
	ordererTLSHostnameOverride   = "orderer.example.com"

	//msp
	mspID = "Org1MSP"
	// msp 路径
	mspConfigPath = baseAddr + "peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
	//bccsp/idemix 默认bccsp
	mspType = "bccsp"

	mspID2 = "Org2MSP"
	// msp 路径
	mspConfigPath2 = baseAddr + "peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp"
)

func main() {
	peerpath := filepath.Join(os.Getenv("GOPATH"), "src/hyperledger-fabric-sdk-go")
	hand, err := peerex.InitWithFile("core", peerpath, "./")
	if err != nil {
		fmt.Println("构建配置失败")
		return
	}
	txid, _ := invoketest(hand)
	time.Sleep(3 * time.Second)
	querytest(hand)
	txid, _ = invoketest(hand)
	time.Sleep(3 * time.Second)
	querytest(hand)
	queryTxById(hand, txid)
	queryBlock(hand)

}

func initEnv() {
	// fmt.Println("viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))
	os.Setenv("CORE_PEER_ADDRESS", peerAddress)
	os.Setenv("CORE_PEER_CLIENT_CONNTIMEOUT", peerClientconntimeout)
	os.Setenv("CORE_PEER_TLS_ENABLED", "true")
	os.Setenv("CORE_PEER_TLS_CLIENTAUTHREQUIRED", "false")
	os.Setenv("CORE_PEER_TLS_ROOTCERT_FILE", peerTLSRootCertFile)
	os.Setenv("CORE_PEER_TLS_CLIENTKEY_FILE", peerTLSClientKeyFile)
	os.Setenv("CORE_PEER_TLS_CLIENTCERT_FILE", peerTLSClientCertFile)
	os.Setenv("CORE_LOGGING_LEVEL", "INFO")
	os.Setenv("CORE_PEER_LOCALMSPID", peerLocalMspID)
	os.Setenv("CORE_PEER_TLS_CERT_FILE", peerTLSCertFile)
	os.Setenv("CORE_PEER_TLS_KEY_FILE", peerTLSKeyFile)
	os.Setenv("CORE_PEER_MSPCONFIGPATH", peerMspConfigPath)
	os.Setenv("CORE_PEER_BCCSP_SW_FILEKEYSTORE_KEYSTORE", peerBccspSwFileKeyStoreKeyStore)
	//os.Setenv("CORE_PEER_TLS_SERVERHOSTOVERRIDE", peerTLSServerhostOverride)

	os.Setenv("CORE_ORDERER_ADDRESS", ordererEndpoint)
	os.Setenv("CORE_ORDERER_TLS_ENABLED", "true")
	os.Setenv("CORE_ORDERER_CLIENT_CONNTIMEOUT", "3s")
	os.Setenv("CORE_ORDERER_TLS_CLIENTAUTHREQUIRED", "false")
	os.Setenv("CORE_ORDERER_TLS_ROOTCERT_FILE", ordererTLSRootCertFile)
	os.Setenv("CORE_ORDERER_TLS_CLIENTKEY_FILE", ordererTLSClientKeyFile)
	os.Setenv("CORE_ORDERER_TLS_CLIENTCERT_FILE", ordererTLSClientCertFile)
	os.Setenv("CORE_ORDERER_TLS_SERVERHOSTOVERRIDE", ordererTLSHostnameOverride)
}

func querytest(hand peerex.Handle) {
	fmt.Println("========================= query ......==============")
	args := []string{"a"}
	str, e := hand.Query("query", args)
	if e != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("query error:", e)
		fmt.Println("×××××××××××××××××××××××××××")
		return
	}
	fmt.Println("*****************************")
	fmt.Println("query success,result:", str)
	fmt.Println("*****************************")
}

func invoketest(hand peerex.Handle) (string, error) {

	args := []string{"a", "b", "1"}
	txid, err := hand.Invoke("invoke", args)
	if err != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("invoke error:", err)
		fmt.Println("×××××××××××××××××××××××××××")
		return "", err
	}
	fmt.Println("*****************************")
	fmt.Println("invoke success, txid=:", txid)
	fmt.Println("*****************************")

	return txid, nil

}

// 查询block 信息 利用内置的qscc 查询
func queryBlock(hand peerex.Handle) {
	fmt.Println("========================= queryBlock ......==============")
	//peer chaincode query -C mychannel -n qscc -c '{"Args":["GetChainInfo","mychannel"]}'
	str, e := hand.GetChainInfo()
	if e != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("GetChainInfo error:", e)
		fmt.Println("×××××××××××××××××××××××××××")
		return
	}
	fmt.Println("*****************************")
	fmt.Println("GetChainInfo success,result:", str)
	fmt.Println("*****************************")
	queryBlockHeight(hand)
}

// 查询block 信息 利用内置的qscc 查询
func queryBlockHeight(hand peerex.Handle) {
	fmt.Println("========================= queryBlockHeight ......==============")
	//peer chaincode query -C mychannel -n qscc -c '{"Args":["GetChainInfo","mychannel"]}'
	h, e := hand.GetBlcokHeight()
	if e != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("GetChainInfo error:", e)
		fmt.Println("×××××××××××××××××××××××××××")
		return
	}
	fmt.Println("*****************************")
	fmt.Println("GetChainInfo success,result:", h)
	fmt.Println("*****************************")

	queryBlockByNumber(hand, h)
}

// 查询block 信息 利用内置的qscc 查询
func queryTxById(hand peerex.Handle, id string) {
	//"158b0cd7ddcfc5ebf90cfe40b3c37a5e4cc7ef77b46b5efcb8d72ea677d511cc"
	fmt.Println("========================= queryTxById ......==============")
	//peer chaincode query -C mychannel -n qscc -c '{"Args":["GetChainInfo","mychannel"]}'
	str, e := hand.GetTransactionByID(id)
	if e != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("GetTransactionByID error:", e)
		fmt.Println("×××××××××××××××××××××××××××")
		return
	}
	fmt.Println("*****************************")
	fmt.Println("GetTransactionByID success,result:", str)
	fmt.Println("*****************************")
}

func queryBlockByNumber(hand peerex.Handle, h int64) {
	fmt.Println("========================= queryBlockByNumber ......==============")
	if h >= 1 {
		h = h - 1
	}
	str, e := hand.GetBlockByNumber(h)
	if e != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("GetBlockByNumber error:", e)
		fmt.Println("×××××××××××××××××××××××××××")
		return
	}
	fmt.Println("*****************************")
	fmt.Println("GetBlockByNumber success,result:", str)
	fmt.Println("*****************************")
}
