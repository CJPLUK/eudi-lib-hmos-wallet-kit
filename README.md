# eudi_lib_wallet_kit

EU Digital Identity Wallet 的**协议门面 / 集成枢纽**(仓颉 / HarmonyOS),移植自欧盟委员会官方参考实现 [eudi-lib-ios-wallet-kit](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-wallet-kit)。

> `EudiWallet` 把签发(OpenID4VCI)、出示(OpenID4VP + mdoc BLE 近场)、文档存储、密钥、状态、日志编排成统一的钱包公共 API。消费 **11 个上游模块**——是整个 EUDI 仓颉栈的集成顶点。

## 功能(6 层 + 门面)

| 子域 | 能力 | 消费上游 |
|---|---|---|
| **models** | 配置(EudiWalletConfiguration/OpenId4VCIConfiguration/OpenId4VpConfiguration)/错误(WalletError)/DocElements/枚举/签发模型 | mdoc-data-model |
| **storage** | StorageManager:文档加载/删除/状态/内存列表编排 | wallet-storage |
| **support** | SecureAreaSigner(签名)/SdJwtUtils/TrustedChainValidator(x509)/DocumentStatusService(statium)/TransactionLog/FileLogging/DcqlQueryable | mdoc-security/sd-jwt/x509/statium |
| **issuance** | OpenId4VciService:OpenID4VCI 凭证签发(授权/token/credential/deferred/batch) | openid4vp-vci |
| **presentation** | OpenID4VP 远程出示 + mdoc BLE 近场出示(OpenId4VpService/PresentationSession/BlePresentationService) | openid4vp-vci/mdoc-transfer |
| **facade** | **EudiWallet** 主门面 ~25 API:beginIssue/endIssue/issueDocuments/beginPresentation/load/delete/getDocumentStatus... | (编排全部下层)|

## 仓库结构

```
eudi_lib_wallet_kit/
├── eudi_cjwallet_kit/              ← HAR 模块(pkg ohos_app_cangjie_eudi_cjwallet_kit)
│   ├── src/main/cangjie/index.cj   ← runEudiWalletDemo()(EudiWallet 装配 + 非网络自检)
│   └── src/main/cangjie/wallet/    ← models / storage / support / issuance / presentation / facade
├── entry/                         ← 测试面板 HAP(36 个非网络设备 E2E + "Run Wallet-Kit Demo")
│   └── libs/{stdx, arm64-v8a}/    ← stdx 1.1.3.1 + OpenSSL/libsecurec 运行时件
├── hvigorfile.ts                  ← 根:auto-fetch IIFE,构建期自动 clone 11 依赖到父目录(sibling)
└── (依赖为本仓库 sibling,由 hvigorfile 拉取;非仓库内 third_party)
```

## 上游依赖(sibling-dep 规范 — auto-fetch hvigorfile)

本库消费 **11 个上游 external_repo_module**,采用团队 sibling-dep 规范(见 blueprint `integration_modes`):

- HAR `cjpm.toml` 用 `../../eudi_lib_<x>/eudi_cj<x>` 引各依赖(deps 为本仓库的 sibling)。
- 根 `hvigorfile.ts` 顶部有 auto-fetch IIFE(依赖解析前执行):按锁定 ref 把 11 个依赖仓 `git clone` 到本仓库的**父目录**(sibling),幂等;已存在则跳过。clone 列表 = 下面 11 个 @ v0.1.0。
- 因此**独立 clone 本仓库构建时无需手动准备依赖**——hvigorfile 自动拉取。壳工程消费时由壳的 hvigorfile 把全部模块平铺进 `third_party/`,`../../` 在平铺层内解析。

依赖闭包(11,均 v0.1.0):
```
eudi_lib_cbor / eudi_lib_core_crypto / eudi_lib_jose / eudi_lib_x509 / eudi_lib_statium /
eudi_lib_mdoc_data_model / eudi_lib_sdjwt / eudi_lib_mdoc_security / eudi_lib_mdoc_transfer /
eudi_lib_wallet_storage / eudi_lib_openid4vp_vci
```

> **stdx 版本 1.1.3.1**(110 文件,含 `stdx.crypto.common`);旧 beta 会致上游编译失败(lib-packaging-spec §10)。

## 下游消费(sibling-dep)

壳/上层工程把本仓库与其依赖平铺为 sibling(由壳 hvigorfile auto-fetch),消费方模块用 `../../` 引本库:

```toml
[dependencies]
  [dependencies.ohos_app_cangjie_eudi_cjwallet_kit]
    path = "../../eudi_lib_wallet_kit/eudi_cjwallet_kit"
```

```cangjie
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.facade.*   // EudiWallet
import ohos_app_cangjie_eudi_cjwallet_kit.wallet.models.*
```

## 构建与验证

构建命令、环境变量、运行时件要求同团队 lib-packaging-spec,参照 [eudi_lib_mdoc_security](https://github.com/CJPLUK/eudi-lib-hmos-mdoc-security) README。

- **36 个设备端 E2E**(非网络范围,真机独立核实 failures=0):wk_models 类型/错误/配置 26 + wk_facade EudiWallet 装配 7 + app_shell demo 3。
- 测试面板:app 内点 **Run Wallet-Kit Demo** → `OK: wallet_assembled=PASS, doc_mgmt=PASS, note=issuance/presentation require network (not in self-test)`。

> **E2E 范围说明**:签发(OpenID4VCI,需 OAuth/issuer server)、出示(OpenID4VP,需 verifier;mdoc BLE 需双机)走网络/双机,**不在自包含设备 E2E 范围**——这些是集成流程,需真实服务端/对端联调验证。非网络的类型/配置/门面装配/文档管理路径已设备实证。

## License

[Apache License 2.0](LICENSE)。本项目为 eudi-lib-ios-wallet-kit(© European Commission)的衍生移植,归属与捆绑件声明见 [NOTICE](NOTICE)。
