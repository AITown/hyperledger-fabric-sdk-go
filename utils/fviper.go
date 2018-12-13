package utils

import (
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

//InitViper we can set viper which fabric node is used
func InitViper(envprefix string, filename string, configPath ...string) error {
	// viper.SetEnvPrefix(envprefix)
	viper.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	for _, c := range configPath {
		viper.AddConfigPath(c)
	}

	viper.SetConfigName(filename) // Name of config file (without extension)

	//这个是fabric内部使用的,msp等会使用他
	// err := fcommon.InitConfig("core")
	// if err != nil {
	// 	fmt.Println(" common.InitConfig core 失败", err)
	// }
	return viper.ReadInConfig() // Find and read the config file

}

//New or create another one for ourself
func New() *viper.Viper {
	return viper.New()
}

//GetReplaceKeyAbsPath 如果rawKey 的值为空 则取repalceKey的值  raw是否使用的是原始的key
func GetReplaceKeyAbsPath(rawKey, repalceKey string) (value string, raw bool) {

	if viper.GetString(rawKey) == "" {
		value = GetAbsPath(repalceKey)
	} else {
		value = GetAbsPath(rawKey)
		raw = true
	}
	return
}

//GetAbsPath 获取配置文件的对应值
func GetAbsPath(key string) string {
	logger.Debug("viper get key", key)
	p := viper.GetString(key)
	if p == "" {
		return ""
	}
	return TranslatePath(filepath.Dir(viper.ConfigFileUsed()), p)
}

func TranslatePath(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}

	return filepath.Join(base, p)
}
