#### hyperledger-fabirc-go-sdk


+ 目前只有invoke 、query功能
+ 利用fabric的cli代码改造的
+ 可用于1.2版本网络,其他的没有测试过
+ client.go 是代码示例
+ core.yaml是配置文件 是配置文件，不过目前只有日志级别，输出 读取了配置文件
  


注
+ Gopkg.lock 不应该上传并且做修改的，但是最开始用dep 解析后编译有问题，对Gopkg.lock部分版本做了修改，不过再对代码逻辑进行了部分修改后，再次dep ensure 是没有问题，此处暂时还是保留

+ sdk 逻辑
   + 一开始初始化msp 密钥信息
   + 创建peer orderer节点的grpc 连接
   + invoke、query 操作
   + invoke 操作完，可选是否需要各个peer节点回执