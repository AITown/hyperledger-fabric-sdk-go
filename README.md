#### hyperledger-fabirc-go-sdk


+ 目前只有invoke 、query功能
+ 利用fabric的cli代码改造的
+ 可用于1.2版本网络,其他的没有测试过
+ client.go 是代码示例，core.yaml是配置文件


+ 目前没有进行版本管理，可以git clone fabric 源码之后 checkout 到1.2  


注
+ Gopkg.lock 不应该上传并且做修改的，但是用dep init的编译有问题，所以对Gopkg.lock做了部分版本修改