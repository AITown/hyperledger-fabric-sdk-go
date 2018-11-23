package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	//"github.com/hyperledger/fabric/peer/common"
	"hyperledger-fabric-sdk-go/peerex"
	"hyperledger-fabric-sdk-go/peerex/utils"
)

const (
	//baseAddr = "/opt/gopath/src/github.com/hyperledger/fabric/peer/crypto/"
	baseAddr    = "/home/gjf/hyperledger-fabric/fabric-samples/first-network/crypto-config/"
	peerAddress = "0.0.0.0:7051"
	//peerAddress                     = "peer0.org1.example.com:7051"
	peerTLSRootCertFile             = baseAddr + "peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
	peerClientconntimeout           = "30s"
	peerTLSEnabled                  = "true"
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
	peerTLSRootCertFile1       = baseAddr + "peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
	peerTLSServerhostOverride1 = "peer0.org2.example.com"

	//order 配置
	ordererEndpoint = "0.0.0.0:7050"
	//ordererEndpoint              = "orderer.example.com:7050"
	ordererTLS                   = "true"
	ordererConnTimeout           = 3 * time.Second
	ordererTLSClientAuthRequired = "false"
	ordererTLSRootCertFile       = baseAddr + "ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem"
	ordererTLSClientKeyFile      = ""
	ordererTLSClientCertFile     = ""
	ordererTLSHostnameOverride   = "orderer.example.com"
)

func init() {

	peerpath := filepath.Join(os.Getenv("GOPATH"), "src/hyperledger.abchain.org/client/fabric_1.2")
	if err := utils.InitPeerViper("core", "core", "./", peerpath); err != nil {
		fmt.Println("utils.InitPeerViper faile:", err)
	}

	//initEnv()
}
func main() {
	//initEnv()
	//	querytest()
	//invoketest()
	querytest()

}

func initEnv() {
	// fmt.Println("viper.ConfigFileUsed:", filepath.Dir(viper.ConfigFileUsed()))
	os.Setenv("CORE_PEER_ADDRESS", peerAddress)
	os.Setenv("CORE_PEER_CLIENT_CONNTIMEOUT", peerClientconntimeout)
	os.Setenv("CORE_PEER_TLS_ENABLED", peerTLSEnabled)
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
	r := &peerex.RPCBuilder{
		Function:         "query",
		ChaincodeName:    "mycc",
		ChaincodeVersion: "1.0",
		ChannelID:        "mychannel",
		PeerEnv: peerex.PeerEnv{
			PeerTLS:                   peerTLSEnabled,
			PeerAddresses:             []string{peerAddress},
			PeerTLSRootCertFile:       []string{peerTLSRootCertFile},
			PeerTLSHostnameOverride:   []string{peerTLSServerhostOverride},
			PeerTLSClientAuthRequired: "true",
		},
	}

	args := []string{"a"}
	str, e := r.Query(args)
	if e != nil {
		fmt.Println("result,error:", e)
	}
	fmt.Println("result:", str)
}

func invoketest() {
	r := &peerex.RPCBuilder{
		Function:         "invoke",
		ChaincodeName:    "mycc",
		ChaincodeVersion: "1.0",
		ChannelID:        "mychannel",
		WaitForEvent:     true,

		PeerEnv: peerex.PeerEnv{
			PeerTLS:                 peerTLSEnabled,
			PeerAddresses:           []string{peerAddress, peerAddress1},
			PeerTLSRootCertFile:     []string{peerTLSRootCertFile, peerTLSRootCertFile1},
			PeerTLSHostnameOverride: []string{peerTLSServerhostOverride, peerTLSServerhostOverride1},
		},

		OrderEnv: peerex.OrderEnv{
			OrdererTLS:                   ordererTLS,
			OrdererAddress:               ordererEndpoint,
			OrdererTLSHostnameOverride:   ordererTLSHostnameOverride,
			OrdererConnTimeout:           ordererConnTimeout,
			OrdererTLSClientAuthRequired: ordererTLSClientAuthRequired,
			OrdererTLSRootCertFile:       ordererTLSRootCertFile,
			OrdererTLSClientKeyFile:      ordererTLSClientKeyFile,
			OrdererTLSClientCertFile:     ordererTLSClientCertFile,
		},
	}

	args := []string{"b", "a", "10"}
	txid, e := r.Invoke(args)
	if e != nil {
		fmt.Println("result,error:", e)
	}
	fmt.Println("success,txid=:", txid)
}
