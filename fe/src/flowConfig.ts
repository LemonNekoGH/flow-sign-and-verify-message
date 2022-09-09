import * as fcl from '@onflow/fcl'

// Flow 的配置
fcl.config({
  'accessNode.api': 'http://localhost:8888', // Mainnet: "https://rest-mainnet.onflow.org"
  'discovery.wallet': 'http://localhost:8701/fcl/authn', // Mainnet: "https://fcl-discovery.onflow.org/authn"
  '0xProfile': '0xba1132bc08f82fe2', // 这个合约是用来查询账户信息的
  'app.detail.icon': 'https://www.mono.fun/apple-touch-icon.png?v=1',
  'app.detail.title': 'Mono',
})
