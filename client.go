package main

import (
	"fmt"
	"hyperledger-fabric-sdk-go/peerex"
	"os"
	"path/filepath"
	"time"

	//"github.com/hyperledger/fabric/peer/common"

	"hyperledger-fabric-sdk-go/peerex/utils"
)

const (
	//baseAddr = "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/"
	baseAddr    = "/home/gjf/hyperledger-fabric/fabric-samples/first-network/crypto-config/"
	peerAddress = "0.0.0.0:7051"
	//peerAddress                     = "peer0.org1.example.com:7051"
	peerTLSRootCertFile             = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
	peerClientconntimeout           = "30s"
	peerTLSEnabled                  = true
	peerTLSClientAuthRequired       = "false"
	peerTLSClientKeyFile            = ""
	peerTLSClientCertFile           = ""
	peerLocalMspID                  = "Org1MSP"
	peerTLSCertFile                 = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.crt"
	peerTLSKeyFile                  = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/server.key"
	peerMspConfigPath               = baseAddr + "peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
	peerBccspSwFileKeyStoreKeyStore = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp"
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
	ordererTLSClientAuthRequired = false
	ordererTLSRootCertFile       = baseAddr + "ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
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
	//initEnv()
	//	querytest()
	invoketest()
	//querytest()

}

func initEnv() {
	// fmt.Println("viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))
	os.Setenv("CORE_PEER_ADDRESS", peerAddress)
	os.Setenv("CORE_PEER_CLIENT_CONNTIMEOUT", peerClientconntimeout)
	os.Setenv("CORE_PEER_TLS_ENABLED", "true")
	os.Setenv("CORE_PEER_TLS_CLIENTAUTHREQUIRED", peerTLSClientAuthRequired)
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
	r.ChaincodeVersion = "1.0"
	r.ChannelID = "mychannel"

	r.WaitForEvent = true

	p := peerex.OnePeer{}

	p.PeerTLS = peerTLSEnabled
	p.PeerAddresses = peerAddress
	p.PeerTLSRootCertFile = peerTLSRootCertFile
	p.PeerTLSHostnameOverride = peerTLSServerhostOverride
	p.PeerTLSKeyFile = peerTLSKeyFile
	p.PeerTLSCertFile = peerTLSCertFile
	p.PeerTLSClientAuthRequired = true

	r.Peers = append(r.Peers, p)
	r.MspID = mspID
	r.MspType = mspType
	r.MspConfigPath = mspConfigPath

	args := []string{"a"}
	str, e := r.Query("query", args)
	if e != nil {
		fmt.Println("result,error:", e)
	}
	fmt.Println("result:", str)
}

func invoketest() {
	r := peerex.NewRpcBuilder()
	r.Function = "invoke"
	r.ChaincodeName = "mycc"
	r.ChaincodeVersion = "1.0"
	r.ChannelID = "mychannel"
	r.WaitForEvent = true

	p1 := peerex.OnePeer{}

	p1.PeerTLS = peerTLSEnabled
	p1.PeerAddresses = peerAddress
	p1.PeerTLSRootCertFile = peerTLSRootCertFile
	p1.PeerTLSHostnameOverride = peerTLSServerhostOverride
	p1.PeerTLSKeyFile = peerTLSKeyFile
	p1.PeerTLSCertFile = peerTLSCertFile
	p1.PeerTLSClientAuthRequired = true

	p2 := peerex.OnePeer{}

	p2.PeerTLS = peerTLSEnabled
	p2.PeerAddresses = peerAddress1
	p2.PeerTLSRootCertFile = peerTLSRootCertFile1
	p2.PeerTLSHostnameOverride = peerTLSServerhostOverride1
	p2.PeerTLSKeyFile = peerTLSKeyFile1
	p2.PeerTLSCertFile = peerTLSCertFile1
	p2.PeerTLSClientAuthRequired = true

	r.Peers = append(r.Peers, p1, p2)

	// r.PeerTLS = peerTLSEnabled
	// r.PeerAddresses = []string{peerAddress, peerAddress1}
	// r.PeerTLSRootCertFile = []string{peerTLSRootCertFile, peerTLSRootCertFile1}
	// r.PeerTLSHostnameOverride = []string{peerTLSServerhostOverride, peerTLSServerhostOverride1}
	r.MspID = mspID
	r.MspType = mspType
	r.MspConfigPath = mspConfigPath

	r.OrdererTLS = ordererTLS
	r.OrdererAddress = ordererEndpoint
	r.OrdererTLSHostnameOverride = ordererTLSHostnameOverride
	r.OrdererConnTimeout = ordererConnTimeout
	r.OrdererTLSClientAuthRequired = ordererTLSClientAuthRequired
	r.OrdererTLSRootCertFile = ordererTLSRootCertFile
	r.OrdererTLSClientKeyFile = ordererTLSClientKeyFile
	r.OrdererTLSClientCertFile = ordererTLSClientCertFile

	args := []string{"a", "b", "1"}
	txid, e := r.Invoke("invoke", args)
	if e != nil {
		fmt.Println("result,error:", e)
	}
	fmt.Println("success,txid=:", txid)
}
