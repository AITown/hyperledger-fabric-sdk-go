package utils

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
	//"github.com/hyperledger/fabric/peer/common"
	fcommon "github.com/hyperledger/fabric/peer/common"
)

//InitPeerViper we can set viper which fabric peer is used
func InitPeerViper(envprefix string, filename string, configPath ...string) error {
	viper.SetEnvPrefix(envprefix)
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	for _, c := range configPath {
		viper.AddConfigPath(c)
	}

	viper.SetConfigName(filename) // Name of config file (without extension)

	fabricCfgPath, _ := os.Getwd()
	os.Setenv("FABRIC_CFG_PATH", fabricCfgPath)
	//这个是fabric内部使用的,msp等会使用他
	err := fcommon.InitConfig("core")
	if err != nil {
		fmt.Println(" common.InitConfig core 失败", err)
	}
	return viper.ReadInConfig() // Find and read the config file

}

//New or create another one for ourself
func New() *viper.Viper {
	return viper.New()
}
