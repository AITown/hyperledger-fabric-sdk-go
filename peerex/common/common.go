package common

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/channelconfig"
	"github.com/hyperledger/fabric/common/viperutil"
	"github.com/hyperledger/fabric/core/comm"
	"github.com/hyperledger/fabric/core/scc/cscc"
	"github.com/hyperledger/fabric/msp"
	mspmgmt "github.com/hyperledger/fabric/msp/mgmt"
	"github.com/hyperledger/fabric/peer/common/api"
	pcommon "github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
	putils "github.com/hyperledger/fabric/protos/utils"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const logsymbol = "peerex_common_comon"

// var logger = utils.MustGetLogger(logsymbol)
var (
	defaultConnTimeout = 3 * time.Second
	// These function variables (xyzFnc) can be used to invoke corresponding xyz function
	// this will allow the invoking packages to mock these functions in their unit test cases

	// GetEndorserClientFnc is a function that returns a new endorser client connection
	// to the provided peer address using the TLS root cert file,
	// by default it is set to GetEndorserClient function
	GetEndorserClientFnc func(address, tlsRootCertFile, hostnameoverride string) (pb.EndorserClient, error)

	// GetPeerDeliverClientFnc is a function that returns a new deliver client connection
	// to the provided peer address using the TLS root cert file,
	// by default it is set to GetDeliverClient function
	GetPeerDeliverClientFnc func(address, tlsRootCertFile, hostnameoverride string) (api.PeerDeliverClient, error)

	// GetDeliverClientFnc is a function that returns a new deliver client connection
	// to the provided peer address using the TLS root cert file,
	// by default it is set to GetDeliverClient function
	//GetDeliverClientFnc func(address, tlsRootCertFile string) (pb.Deliver_DeliverClient, error)

	// GetDefaultSignerFnc is a function that returns a default Signer(Default/PERR)
	// by default it is set to GetDefaultSigner function
	GetDefaultSignerFnc func() (msp.SigningIdentity, error)

	// GetBroadcastClientFnc returns an instance of the BroadcastClient interface
	// by default it is set to GetBroadcastClient function
	GetBroadcastClientFnc func(address, hostnameoverride string) (BroadcastClient, error)

	// GetOrdererEndpointOfChainFnc returns orderer endpoints of given chain
	// by default it is set to GetOrdererEndpointOfChain function
	GetOrdererEndpointOfChainFnc func(chainID string, signer msp.SigningIdentity,
		endorserClient pb.EndorserClient) ([]string, error)

	// GetCertificateFnc is a function that returns the client TLS certificate
	GetCertificateFnc func() (tls.Certificate, error)
)

type commonClient struct {
	*comm.GRPCClient
	address string
	sn      string
}

func init() {
	GetEndorserClientFnc = GetEndorserClient
	GetDefaultSignerFnc = GetDefaultSigner
	GetBroadcastClientFnc = GetBroadcastClient
	GetOrdererEndpointOfChainFnc = GetOrdererEndpointOfChain
	//	GetDeliverClientFnc = GetDeliverClient
	GetPeerDeliverClientFnc = GetPeerDeliverClient
	GetCertificateFnc = GetCertificate

}

// InitCrypto initializes crypto for this peer
func InitCrypto(mspMgrConfigDir, localMSPID, localMSPType string) error {
	var err error
	// Check whether msp folder exists
	fi, err := os.Stat(mspMgrConfigDir)
	if os.IsNotExist(err) || !fi.IsDir() {
		// No need to try to load MSP from folder which is not available
		return errors.Errorf("cannot init crypto, missing %s folder", mspMgrConfigDir)
	}
	// Check whether localMSPID exists
	if localMSPID == "" {
		return errors.New("the local MSP must have an ID")
	}

	// Init the BCCSP
	SetBCCSPKeystorePath()
	var bccspConfig *factory.FactoryOpts
	err = viperutil.EnhancedExactUnmarshalKey("peer.BCCSP", &bccspConfig)
	fmt.Println("initCrypto:", bccspConfig, "common/common.go 97")
	if err != nil {
		return errors.WithMessage(err, "could not parse YAML config")
	}

	err = mspmgmt.LoadLocalMspWithType(mspMgrConfigDir, bccspConfig, localMSPID, localMSPType)
	if err != nil {
		return errors.WithMessage(err, fmt.Sprintf("error when setting up MSP of type %s from directory %s", localMSPType, mspMgrConfigDir))
	}

	return nil
}

// SetBCCSPKeystorePath sets the file keystore path for the SW BCCSP provider
// to an absolute path relative to the config file
func SetBCCSPKeystorePath() {
	if str, b := getReplaceKeyPath("peer.BCCSP.SW.FileKeyStore.KeyStore", "peer.mspConfigPath"); b {
		viper.Set("peer.BCCSP.SW.FileKeyStore.KeyStore", str)
	} else {
		viper.Set("peer.BCCSP.SW.FileKeyStore.KeyStore", filepath.Join(str, "KeyStore"))
	}
}

// GetOrdererEndpointOfChain returns orderer endpoints of given chain
func GetOrdererEndpointOfChain(chainID string, signer msp.SigningIdentity, endorserClient pb.EndorserClient) ([]string, error) {
	// query cscc for chain config block
	invocation := &pb.ChaincodeInvocationSpec{
		ChaincodeSpec: &pb.ChaincodeSpec{
			Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]),
			ChaincodeId: &pb.ChaincodeID{Name: "cscc"},
			Input:       &pb.ChaincodeInput{Args: [][]byte{[]byte(cscc.GetConfigBlock), []byte(chainID)}},
		},
	}

	creator, err := signer.Serialize()
	if err != nil {
		return nil, errors.WithMessage(err, fmt.Sprintf("error serializing identity for %s", signer.GetIdentifier()))
	}

	prop, _, err := putils.CreateProposalFromCIS(pcommon.HeaderType_CONFIG, "", invocation, creator)
	if err != nil {
		return nil, errors.WithMessage(err, "error creating GetConfigBlock proposal")
	}

	signedProp, err := putils.GetSignedProposal(prop, signer)
	if err != nil {
		return nil, errors.WithMessage(err, "error creating signed GetConfigBlock proposal")
	}

	proposalResp, err := endorserClient.ProcessProposal(context.Background(), signedProp)
	if err != nil {
		return nil, errors.WithMessage(err, "error endorsing GetConfigBlock")
	}

	if proposalResp == nil {
		return nil, errors.WithMessage(err, "error nil proposal response")
	}

	if proposalResp.Response.Status != 0 && proposalResp.Response.Status != 200 {
		return nil, errors.Errorf("error bad proposal response %d: %s", proposalResp.Response.Status, proposalResp.Response.Message)
	}

	// parse config block
	block, err := putils.GetBlockFromBlockBytes(proposalResp.Response.Payload)
	if err != nil {
		return nil, errors.WithMessage(err, "error unmarshaling config block")
	}

	envelopeConfig, err := putils.ExtractEnvelope(block, 0)
	if err != nil {
		return nil, errors.WithMessage(err, "error extracting config block envelope")
	}
	bundle, err := channelconfig.NewBundleFromEnvelope(envelopeConfig)
	if err != nil {
		return nil, errors.WithMessage(err, "error loading config block")
	}

	return bundle.ChannelConfig().OrdererAddresses(), nil
}

//GetDefaultSigner 获取默认签名
func GetDefaultSigner() (msp.SigningIdentity, error) {
	signer, err := mspmgmt.GetLocalMSP().GetDefaultSigningIdentity()
	if err != nil {
		return nil, errors.WithMessage(err, "error obtaining the default signing identity")
	}

	return signer, err
}

var count = 1

func configFromEnv(prefix string) (address, override string, clientConfig comm.ClientConfig, err error) {
	address = viper.GetString(prefix + ".address")
	override = viper.GetString(prefix + ".tls.serverhostoverride")
	clientConfig = comm.ClientConfig{}
	connTimeout := viper.GetDuration(prefix + ".client.connTimeout")
	if connTimeout == time.Duration(0) {
		connTimeout = defaultConnTimeout
	}
	clientConfig.Timeout = connTimeout
	secOpts := &comm.SecureOptions{
		UseTLS:            viper.GetBool(prefix + ".tls.enabled"),
		RequireClientCert: viper.GetBool(prefix + ".tls.clientAuthRequired")}
	if secOpts.UseTLS {
		caPEM, res := ioutil.ReadFile(GetPath(prefix + ".tls.rootcert.file"))
		if res != nil {
			err = errors.WithMessage(res,
				fmt.Sprintf("unable to load %s.tls.rootcert.file", prefix))
			//return
		}
		secOpts.ServerRootCAs = [][]byte{caPEM}
	}
	if secOpts.RequireClientCert {
		path, _ := getReplaceKeyPath(prefix+".tls.clientKey.file", prefix+".tls.key.file")
		keyPEM, res := ioutil.ReadFile(path)
		if res != nil {
			err = errors.WithMessage(res,
				fmt.Sprintf("unable to load %s.tls.clientKey.file", prefix))
			return
		}
		secOpts.Key = keyPEM
		path, _ = getReplaceKeyPath(prefix+".tls.clientCert.file", prefix+".tls.cert.file")
		certPEM, res := ioutil.ReadFile(path)
		if res != nil {
			err = errors.WithMessage(res,
				fmt.Sprintf("unable to load %s.tls.clientCert.file", prefix))
			return
		}
		secOpts.Certificate = certPEM
	}
	clientConfig.SecOpts = secOpts

	fmt.Println("configFromEnv 第", count, "次", " 前缀是:", prefix, ".address, .tls.serverhostoverride, .client.connTimeout,", address, override, connTimeout)
	fmt.Println("configFromEnv 第", count, "次", " 前缀是:", prefix, ".tls.enabled,.tls.clientAuthRequired", secOpts.UseTLS, secOpts.RequireClientCert)
	fmt.Println("configFromEnv 第", count, "次", " 前缀是:", prefix, ".tls.rootcert.file,", GetPath(prefix+".tls.rootcert.file"))
	count++
	return
}

// 如果rawKey 的值为空 则取repalceKey的值  raw是否使用的是原始的key
func getReplaceKeyPath(rawKey, repalceKey string) (value string, raw bool) {
	if viper.GetString(rawKey) == "" {
		value = GetPath(repalceKey)
	} else {
		value = GetPath(rawKey)
		raw = true
	}
	return
}

//GetPath 获取配置文件的对应值
func GetPath(key string) string {
	p := viper.GetString(key)
	fmt.Printf("viper get key:%s====value:%s,current viper path is:%s \n", key, p, viper.ConfigFileUsed())
	if p == "" {
		return ""
	}
	return translatePath(filepath.Dir(viper.ConfigFileUsed()), p)
}

func translatePath(base, p string) string {
	if filepath.IsAbs(p) {
		return p
	}

	return filepath.Join(base, p)
}
