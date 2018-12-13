package peerex

import (
	"context"
	"fmt"
	mspex "hyperledger-fabric-sdk-go/msp"

	fmsp "github.com/hyperledger/fabric/msp"
	pb "github.com/hyperledger/fabric/protos/peer"
	protoutils "github.com/hyperledger/fabric/protos/utils"

	"github.com/pkg/errors"
)

const (
	query       = "query"
	invoke      = "invoke"
	logsymbol   = "cc"
	errorStatus = 400
)

//Query 查询  格式: args:[]string{"a"} 代表查询a的值 跟方法名要匹配
func (r *RPCBuilder) Query(args []string) (*pb.Response, error) {

	// r.args = args
	err := r.Verify(true)
	if err != nil {
		return nil, err
	}

	err = r.InitConn(false)
	if err != nil {
		return nil, err
	}
	// err = InitCrypto(r.MspEnv)
	// if err != nil {
	// 	return nil, err
	// }

	pb, err := r.ChaincodeQuery(args)
	if err != nil {
		return nil, err
	}

	return pb.Response, nil
}

func (r *RPCBuilder) Invoke(args []string) (string, error) {

	// r.args = args
	if err := r.Verify(false); err != nil {
		return "", err
	}
	// r.InitConfig()
	// InitCrypto(r.MspEnv)

	err := r.InitConn(true)
	if err != nil {
		return "", err
	}

	// err = InitCrypto(r.MspEnv)
	// if err != nil {
	// 	return "", err
	// }

	// defer cf.BroadcastClient.Close()

	_, txid, err := r.ChaincodeInvoke(args)
	if err != nil {
		return "", err
	}
	return txid, nil
	// return r.ChaincodeEnv.Invoke(cf, args)
}

func (r *RPCBuilder) ChaincodeQuery(args []string) (*pb.ProposalResponse, error) {
	peer := r.Peers[0]
	c := r.ChaincodeEnv
	signer, err := mspex.GetSigningIdentity()
	if err != nil {
		return nil, errors.WithMessage(err, "error getting default signer")
	}
	signedProp, _, _, err := c.creatProposal(signer, args)

	// res, _, _, err := c.execute(cf, args)
	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status

	proposalResp, err := peer.NewEndorserClient().ProcessProposal(context.Background(), signedProp)
	if err != nil {
		return nil, err
	}
	if proposalResp == nil {
		return nil, errors.New("error during query: received nil proposal response")
	}
	if proposalResp.Endorsement == nil {
		return nil, errors.Errorf("endorsement failure during query. response: %v", proposalResp.Response)
	}

	return proposalResp, nil
}

func (r *RPCBuilder) ChaincodeInvoke(args []string) (*pb.ProposalResponse, string, error) {
	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status
	// responses, txid, prop, err := c.execute(cf, args)
	c := r.ChaincodeEnv
	signer, err := mspex.GetSigningIdentity()
	if err != nil {
		return nil, "", errors.WithMessage(err, "error getting default signer")
	}
	signedProp, txid, prop, err := c.creatProposal(signer, args)
	if err != nil {
		return nil, "", err
	}
	var responses []*pb.ProposalResponse

	for _, peer := range r.Peers {
		//使用grpc调用endorserClient.ProcessProposal，触发endorer执行proposal  调用invoke query
		proposalResp, err := peer.NewEndorserClient().ProcessProposal(context.Background(), signedProp)
		if err != nil {
			return nil, "", errors.WithMessage(err, "error endorsing ")
		}
		responses = append(responses, proposalResp)
	}
	// all responses will be checked when the signed transaction is created.
	// for now, just set this so we check the first response's status
	proposalResp := responses[0]
	//得到proposalResponse，如果是查询类命令直接返回结果；
	//如果是执行交易类，需要对交易签名CreateSignedTx，然后调用BroadcastClient发送给orderer进行排序，返回response

	if proposalResp != nil {
		if proposalResp.Response.Status >= errorStatus {
			return proposalResp, "", nil
		}
		// assemble a signed transaction (it's an Envelope message) 对交易签名CreateSignedTx
		env, err := protoutils.CreateSignedTx(prop, signer, responses...)
		if err != nil {
			return proposalResp, "", errors.WithMessage(err, "could not assemble transaction")
		}
		logger.Debug("ChaincodeInvokeOrQuery protoutils.CreateSignedTx 成功")

		// send the envelope for ordering  调用BroadcastClient发送给orderer进行排序
		// r.OrderEnv.NodeEnv.New
		bc, err := r.OrderEnv.NewBroadcastClient()
		if err != nil {
			return proposalResp, "", errors.WithMessage(err, "error sending transaction")
		}
		// 发送给orderer
		if err = bc.Send(env); err != nil {
			return proposalResp, "", errors.WithMessage(err, "error sending transaction")
		}
		defer bc.Close()

	}
	logger.Debug("invoke get txid", txid)
	// fmt.Println(string(proposalResp.GetPayload()))
	// fmt.Println(proposalResp.GetTimestamp())
	// fmt.Println(proposalResp.GetVersion())
	// fmt.Println(proposalResp.Response.GetMessage(), "======", proposalResp.Response.GetStatus(), "======", string(proposalResp.Response.GetPayload()))

	// fmt.Println(string(proposalResp.GetEndorsement().GetEndorser()))

	// fmt.Println(string(proposalResp.GetEndorsement().GetSignature()))

	return proposalResp, txid, nil
}

func (c *ChaincodeEnv) creatProposal(signer fmsp.SigningIdentity, args []string) (*pb.SignedProposal, string, *pb.Proposal, error) {
	var (
		tMap      map[string][]byte
		channelID = c.ChannelID
		spec      = c.getChaincodeSpec(args)
	)

	// r.ChaincodeEnv.Signer = signer
	// Build the ChaincodeInvocationSpec message 创建chaincode执行描述结构，创建proposal
	// invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
	creator, err := signer.Serialize()
	if err != nil {
		return nil, "", nil, errors.WithMessage(err, fmt.Sprintf("error serializing identity for %s", signer.GetIdentifier()))
	}

	//prop, txid, err := protoutils.CreateChaincodeProposalWithTxIDAndTransient(fcommon.HeaderType_ENDORSER_TRANSACTION, channelID, invocation, creator, "", tMap)
	prop, txid, err := CreateChaincodeProposalWithTxIDAndTransient(channelID, spec, creator, tMap)
	logger.Debug(" ChaincodeInvokeOrQuery CreateChaincodeProposalWithTxIDAndTransient", txid)
	if err != nil {
		return nil, "", nil, errors.WithMessage(err, "error creating proposal")
	}

	//对proposal签名
	//signedProp, err := protoutils.GetSignedProposal(prop, cf.Signer)
	signedProp, err := GetSignedProposal(prop, signer)

	if err != nil {
		return nil, "", nil, errors.WithMessage(err, "error creating signed proposal ")
	}
	logger.Debug("ChaincodeInvokeOrQuery GetSignedProposal==== success")

	return signedProp, txid, prop, nil
}
