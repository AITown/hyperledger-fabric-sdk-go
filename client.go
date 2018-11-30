package main

import (
	"fmt"
	"hyperledger-fabric-sdk-go/peerex"
	"os"
	"path/filepath"
	"time"

	//"github.com/hyperledger/fabric/peer/common"

	"hyperledger-fabric-sdk-go/utils"
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
)

func init() {

	peerpath := filepath.Join(os.Getenv("GOPATH"), "src/hyperledger-fabric-sdk-go")
	if err := utils.InitViper("core", "core", "./", peerpath); err != nil {
		fmt.Println("utils.InitViper faile:", err)
	}

	//initEnv()
}
func main() {
	invoketest()
	fmt.Println("========================= query ......==============")
	time.Sleep(3 * time.Second)
	querytest()

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

func querytest() {
	r := peerex.NewRpcBuilder()
	r.Function = "query"
	r.ChaincodeName = "mycc"
	// r.ChaincodeVersion = "1.0"
	r.ChannelID = "mychannel"

	p := &peerex.PeerEnv{}

	p.Address = peerAddress
	p.HostnameOverride = peerTLSServerhostOverride

	p.TLS = peerTLSEnabled
	p.RootCertFile = peerTLSRootCertFile

	p.TLSClient = peerTLSClientAuthRequired
	p.KeyFile = peerTLSKeyFile
	p.CertFile = peerTLSCertFile

	r.Peers = append(r.Peers, p)
	r.MspID = mspID
	r.MspType = mspType
	r.MspConfigPath = mspConfigPath

	args := []string{"a"}
	str, e := r.Query("query", args)
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

func invoketest() {
	r := peerex.NewRpcBuilder()
	r.Function = "invoke"
	r.ChaincodeName = "mycc"
	r.ChannelID = "mychannel"

	r.MspID = mspID
	r.MspType = mspType
	r.MspConfigPath = mspConfigPath

	p1 := &peerex.PeerEnv{}

	p1.Address = peerAddress
	p1.HostnameOverride = peerTLSServerhostOverride

	p1.TLS = peerTLSEnabled
	p1.RootCertFile = peerTLSRootCertFile

	p1.TLSClient = peerTLSClientAuthRequired
	p1.KeyFile = peerTLSKeyFile
	p1.CertFile = peerTLSCertFile

	p2 := &peerex.PeerEnv{}

	p2.Address = peerAddress1
	p2.HostnameOverride = peerTLSServerhostOverride1

	p2.TLS = peerTLSEnabled
	p2.RootCertFile = peerTLSRootCertFile1

	p2.TLSClient = peerTLSClientAuthRequired
	p2.KeyFile = peerTLSKeyFile1
	p2.CertFile = peerTLSCertFile1

	r.Peers = append(r.Peers, p1, p2)

	r.Address = ordererEndpoint
	r.HostnameOverride = ordererTLSHostnameOverride
	r.ConnTimeout = ordererConnTimeout

	r.TLS = ordererTLS
	r.RootCertFile = ordererTLSRootCertFile

	r.TLSClient = ordererTLSClientAuthRequired
	r.KeyFile = ordererTLSKeyFile
	r.CertFile = ordererTLSCertFile
	// r.OrdererTLSClientKeyFile = ordererTLSClientKeyFile
	// r.OrdererTLSClientCertFile = ordererTLSClientCertFile

	args := []string{"a", "b", "1"}
	txid, err := r.Invoke("invoke", args)
	if err != nil {
		fmt.Println("×××××××××××××××××××××××××××")
		fmt.Println("invoke error:", err)
		fmt.Println("×××××××××××××××××××××××××××")
		return
	}
	fmt.Println("*****************************")
	fmt.Println("invoke success, txid=:", txid)
	fmt.Println("*****************************")
}
