# sign-and-verify-message
一个用 `fcl` 在前端给消息进行签名，并发送给后端以取得 [`jwt`](https://jwt.io/) 的示例，将来有可能扩展到其它区块链的应用中。为了快速看到 `jwt` 过期后的效果，只设置了两分钟过期时间。

## 大致流程图
![flow](http://processon.com/chart_image/63182730f346fb55d8a48078.png)

## 运行本示例的前置需求
1. [`flow-cli`](https://developers.flow.com/tools/flow-cli) 用于启动 [`Flow`](https://flow.com/) 区块链模拟器，和 [`dev-wallet`](https://github.com/onflow/fcl-dev-wallet)
2. [`golang`](https://go.dev/) 后端使用的语言
3. [`pnpm`](https://pnpm.io/) 前端的包管理器

## 启动本示例
前往后端文件夹
```bash
$ cd be
```
启动 `Flow` 区块链模拟器
```bash
$ flow emulator
```
部署 `FCLCrypto` 辅助合约
```bash
$ flow deploy
```
启动 `dev-wallet`
```bash
$ flow dev-wallet
```
启动后端
```bash
$ go run main.go
```
前往前端文件夹
```bash
$ cd fe
```
安装依赖
```bash
$ pnpm i
```
启动前端项目
```bash
$ pnpm dev
```
所有步骤完成后，就可以在 `localhost:3337` 访问到示例页面了。  
如有任何问题，欢迎开 `issue` 或给柠喵发送邮件。