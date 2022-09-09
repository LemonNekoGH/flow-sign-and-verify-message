/// <reference types="vite/client" />

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}

declare module '@onflow/fcl' {
  declare const getTransactionStatus: (id: string) => void
  declare const send: (args: any[]) => Promise<any>
  declare const decode: (res: any) => any
  declare const query: (arg: {cadence: string; args: any; limit: number}) => any
  declare const arg: (value: any, type: any) => any
  declare const script: any
  declare const currentUser: any
  declare const logIn: (...arg: any[]) => any
  declare const unauthenticate: (...arg: any[]) => any
  declare const mutate: (...arg: any[]) => any
  declare const authz: (...arg: any[]) => any
  declare const config: (arg: Record<string, string>) => void
  export {
    getTransactionStatus,
    send,
    decode,
    config,
    query,
    arg,
    script,
    currentUser,
    logIn,
    unauthenticate,
    mutate,
    authz,
  }
}
