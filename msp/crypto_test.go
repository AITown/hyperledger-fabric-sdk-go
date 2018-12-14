package msp

import (
	"fmt"
	"testing"

	"github.com/hyperledger/fabric/bccsp/factory"
)

func TestInitCrypto(t *testing.T) {
	dir := "/home/gjf/hyperledger-fabric/fabric-samples/first-network/crypto-config/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp"
	id := "Org1MSP"
	ty := "bccsp"
	msp := &MspEnv{
		id,
		dir,
		ty,
	}

	b, err := msp.InitCrypto()
	if err != nil {
		t.Fatal("err", err)
	}

	printbccsp(b)
}

func printbccsp(config *factory.FactoryOpts) {

	fmt.Println(`ProviderName`, config.ProviderName)
	if config.PluginOpts != nil {
		fmt.Println(`PluginOpts.Library`, config.PluginOpts.Library)
		fmt.Println(`PluginOpts.Config`, config.PluginOpts.Config)
	}

	if config.SwOpts != nil {
		fmt.Println(`SwOpts.Ephemeral`, config.SwOpts.Ephemeral)
		fmt.Println(`SwOpts.HashFamily`, config.SwOpts.HashFamily)
		fmt.Println(`SwOpts.SecLevel`, config.SwOpts.SecLevel)
		if config.SwOpts.FileKeystore != nil {
			fmt.Println(`SwOpts.FileKeystore`, config.SwOpts.FileKeystore)
		}
		if config.SwOpts.DummyKeystore != nil {
			fmt.Println(`SwOpts.DummyKeystore`, config.SwOpts.DummyKeystore)
		}
	}

}
