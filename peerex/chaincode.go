package peerex

import (
	"context"
	"fmt"
	"hyperledger-fabric-sdk-go/utils"

	fcommon "github.com/hyperledger/fabric/protos/common"
	pb "github.com/hyperledger/fabric/protos/peer"
	protoutils "github.com/hyperledger/fabric/protos/utils"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
)

const (
	query       = "query"
	invoke      = "invoke"
	logsymbol   = "cc"
	errorStatus = 400
)

// 该日志 来自fabric_1.2 ，现在是输出到终端。需要添加输出到文件的
var logger = utils.MustGetLogger(logsymbol)

func initLog() {
	l := viper.GetString("logging.level")
	utils.SetModuleLevel("^"+logsymbol, l)
	format := viper.GetString("logging.format")
	utils.SetFormat(format)
}

//Query 查询  格式: args:[]string{"a"} 代表查询a的值 跟方法名要匹配
func (r *rPCBuilder) Query(args []string) (string, error) {
	initLog()
	r.args = args
	err := r.Verify(true)
	if err != nil {
		return "", err
	}

	// r.InitConfig()
	err = InitCrypto(r.MspEnv)
	if err != nil {
		return "", err
	}

	logger.Debug("========InitFactory start:============")
	cf, err := r.InitFactory(false)
	if err != nil {
		return "", err
	}
	pb, _, err := r.handle(cf, false, args)
	if err != nil {
		return "", nil
	}
	return string(pb.Response.Payload), nil
	// return r.ChaincodeEnv.Query(cf, args)
}

func (r *rPCBuilder) Invoke(args []string) (string, error) {
	initLog()
	r.args = args
	if err := r.Verify(false); err != nil {
		return "", err
	}
	// r.InitConfig()
	InitCrypto(r.MspEnv)
	cf, err := r.InitFactory(true)
	if err != nil {
		return "", err
	}

	defer cf.BroadcastClient.Close()
	_, txid, err := r.handle(cf, true, args)
	if err != nil {
		return "", err
	}
	return txid, nil
	// return r.ChaincodeEnv.Invoke(cf, args)
}

func (r *rPCBuilder) handle(cf *ChaincodeFactory, invoke bool, args []string) (*pb.ProposalResponse, string, error) {

	// call with empty txid to ensure production code generates a txid.
	// otherwise, tests can explicitly set their own txid
	spec := r.ChaincodeEnv.getChaincodeSpec(args)

	//proposalResp, _, err := ChaincodeInvokeOrQuery(spec, rpcCommonDate.ChannelID, txID, false, cf.Signer, cf.Certificate, cf.EndorserClients, cf.DeliverClients, cf.BroadcastClient)

	var (
		proposalResp *pb.ProposalResponse
		txid         string
		err          error
	)

	if invoke {
		padd := r.GetPeerAddresses()
		proposalResp, txid, err = r.ChaincodeEnv.ChaincodeInvoke(cf, spec, padd)
	} else {
		proposalResp, err = r.ChaincodeEnv.ChaincodeQuery(cf, spec)
	}
	if err != nil {
		return nil, "", errors.Errorf("%s - proposal response: %v", err, proposalResp)
	}

	if proposalResp == nil {
		return nil, "", errors.New("error during query: received nil proposal response")
	}
	if proposalResp.Endorsement == nil {
		return nil, "", errors.Errorf("endorsement failure during query. response: %v", proposalResp.Response)
	}

	return proposalResp, txid, nil
}

func (c *ChaincodeEnv) ChaincodeQuery(cf *ChaincodeFactory, spec *pb.ChaincodeSpec) (*pb.ProposalResponse, error) {
	res, _, _, err := cf.execute(spec, c.ChannelID)
	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status
	proposalResp := res[0]
	if err != nil {
		return nil, err
	}
	return proposalResp, nil
}

func (c *ChaincodeEnv) ChaincodeInvoke(cf *ChaincodeFactory, spec *pb.ChaincodeSpec, peerAddress []string) (*pb.ProposalResponse, string, error) {

	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status
	responses, txid, prop, err := cf.execute(spec, c.ChannelID)

	if err != nil {
		return nil, "", err
	}
	proposalResp := responses[0]
	//得到proposalResponse，如果是查询类命令直接返回结果；
	//如果是执行交易类，需要对交易签名CreateSignedTx，然后调用BroadcastClient发送给orderer进行排序，返回response

	if proposalResp != nil {
		if proposalResp.Response.Status >= errorStatus {
			return proposalResp, "", nil
		}
		// assemble a signed transaction (it's an Envelope message) 对交易签名CreateSignedTx
		env, err := protoutils.CreateSignedTx(prop, cf.Signer, responses...)
		if err != nil {
			return proposalResp, "", errors.WithMessage(err, "could not assemble transaction")
		}
		logger.Debug("ChaincodeInvokeOrQuery protoutils.CreateSignedTx 成功")

		var (
			dg  *deliverGroup
			ctx context.Context
		)
		if c.WaitForEvent {
			var cancelFunc context.CancelFunc
			ctx, cancelFunc = context.WithTimeout(context.Background(), c.WaitForEventTimeout)
			defer cancelFunc()

			// padd := rpcCommonDate.GetPeerAddresses()
			dg = newDeliverGroup(cf.DeliverClients, peerAddress, cf.Certificate, c.ChannelID, txid)
			logger.Debug("ChaincodeInvokeOrQuery newDeliverGroup 成功")

			// connect to deliver service on all peers
			err := dg.Connect(ctx)
			if err != nil {
				return nil, "", err
			}
		}

		// send the envelope for ordering  调用BroadcastClient发送给orderer进行排序
		if err = cf.BroadcastClient.Send(env); err != nil {
			return proposalResp, "", errors.WithMessage(err, "error sending transaction")
		}

		if dg != nil && ctx != nil {
			// wait for event that contains the txid from all peers
			err = dg.Wait(ctx)
			if err != nil {
				logger.Debug("invoke success start wait all peer recv")
				return nil, "", err
			}
		}
	}
	logger.Debug("invoke get txid", txid)
	return proposalResp, txid, nil
}

func (cf *ChaincodeFactory) execute(spec *pb.ChaincodeSpec, channelID string) ([]*pb.ProposalResponse, string, *pb.Proposal, error) {
	var (
		responses []*pb.ProposalResponse
		result    string
		tMap      map[string][]byte
	)

	// Build the ChaincodeInvocationSpec message 创建chaincode执行描述结构，创建proposal
	invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

	creator, err := cf.Signer.Serialize()
	if err != nil {
		return nil, "", nil, errors.WithMessage(err, fmt.Sprintf("error serializing identity for %s", cf.Signer.GetIdentifier()))
	}

	prop, txid, err := protoutils.CreateChaincodeProposalWithTxIDAndTransient(fcommon.HeaderType_ENDORSER_TRANSACTION, channelID, invocation, creator, "", tMap)
	logger.Debug(" ChaincodeInvokeOrQuery protoutils.CreateChaincodeProposalWithTxIDAndTransient", txid)
	if err != nil {
		return nil, "", nil, errors.WithMessage(err, "error creating proposal")
	}

	//对proposal签名
	signedProp, err := protoutils.GetSignedProposal(prop, cf.Signer)

	if err != nil {
		return nil, "", nil, errors.WithMessage(err, "error creating signed proposal ")
	}
	logger.Debug("ChaincodeInvokeOrQuery protoutils.GetSignedProposal==== success")
	for _, endorser := range cf.EndorserClients {
		//使用grpc调用endorserClient.ProcessProposal，触发endorer执行proposal
		proposalResp, err := endorser.ProcessProposal(context.Background(), signedProp)
		if err != nil {
			return nil, "", nil, errors.WithMessage(err, "error endorsing ")
		}

		responses = append(responses, proposalResp)
	}

	if len(responses) == 0 {
		// this should only happen if some new code has introduced a bug
		return nil, "", nil, errors.New("no proposal responses received - this might indicate a bug")
	}
	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status
	// proposalResp := responses[0]
	result = txid
	logger.Debug("execute get txid", txid)
	return responses, result, prop, nil
}
