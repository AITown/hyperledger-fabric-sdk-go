package main

import (
	"fmt"
	"hyperledger-fabric-sdk-go/peerex"
	"os"
	"path/filepath"
	"strconv"
	"sync"
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
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		testfabric()
		wg.Done()
	}()
	wg.Wait()
}

func testfabric() {
	peerpath := filepath.Join(os.Getenv("GOPATH"), "src/hyperledger-fabric-sdk-go")
	hand, err := peerex.InitWithFile("core", peerpath, "./")
	if err != nil {
		fmt.Println("构建配置失败")
		return
	}
	querytest(hand)
	txid, _ := invoketest(hand)
	//此处的时间间隔参考fabric的区块生成时间，否则多次同比交易只有一个有效
	time.Sleep(3 * time.Second)
	txid, _ = invoketest(hand)
	time.Sleep(3 * time.Second)
	txid, _ = invoketest(hand)

	wait := make(chan bool)
	go waitFunc(wait)
	<-wait
	querytest(hand)
	txid, _ = invoketest(hand)
	time.Sleep(3 * time.Second)
	txid, _ = invoketest(hand)

	go waitFunc(wait)
	<-wait

	querytest(hand)
	queryTxById(hand, txid)
	queryBlock(hand)

	querytest(hand)
}
func waitFunc(wait chan bool) {
	//此处的时间间隔参考fabric的区块生成时间，否则查询的结果不会变化
	fmt.Println("将会在10 s 后执行查询操作")
	index := 10
	wait1 := time.After(time.Second * 10)
	for {
		select {
		case <-time.After(time.Second):
			index--
			fmt.Print(strconv.Itoa(index) + " ")
		case <-wait1:
			fmt.Println("\n10 s is comming")
			wait <- true
			return
		}
	}

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
