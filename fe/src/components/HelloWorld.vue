<script setup lang="ts">
import { onMounted, ref } from "vue";
import * as fcl from "@onflow/fcl";
import { Buffer } from "buffer";
import axios from "axios";

defineProps<{ msg: string }>();

const currentUser = ref<any>();
// getUserInfo
const getUserInfo = async (token: string) => {
  try {
    // try to use token to get info
    const resp = await axios.get("http://localhost:3336/profile", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });
    if (resp.data.data.address === currentUser.value.addr) {
      // token is valid
      return resp.data;
    }
    return null;
  } catch (e) {
    return null;
  }
};
// try to get info
const getInfo = async () => {
  const token = localStorage.getItem("accessToken")
  const info = await getUserInfo(token!)
  console.log('get user info', info)
  if (!info) {
    fcl.unauthenticate()
  }
}
const setUser = async (u: any) => {
  currentUser.value = u;
  // check local storage
  if (!currentUser.value.addr) return;
  console.log('try to connect as ' + currentUser.value.addr)
  const token = localStorage.getItem("accessToken");
  if (token) {
    console.log('try to use exists token to get info.')
    const info = await getUserInfo(token);
    if (info) return;
  }
  console.log('no token or token is invalid.')
  // token is invalid, should request to sign a message
  const signature = await sign();
  console.log('get signature: ', signature)
  if (!Array.isArray(signature.sig)) {
    // user rejected
    fcl.unauthenticate();
    console.log("wallet connect failed...");
    return;
  }
  console.log('signed a message.')
  // try to verify
  // @ts-expect-error
  console.log('verify at frontend: ', await fcl.AppUtils.verifyUserSignatures(signature.msg, signature.sig, {
    fclCryptoContract: '0xf8d6e0586b0a20c7'
  }))
  // get a token
  try {
    // get keys and sigs
    const keys: number[] = []
    const sigs: string[] = []
    for (const sig of signature.sig) {
      keys.push(sig.keyId)
      sigs.push(sig.signature)
    }
    // request a token
    const resp = await axios.post("http://localhost:3336/login", {
      address: currentUser.value.addr,
      message: signature.msg,
      signatures: sigs,
      keyIndices: keys,
    });
    localStorage.setItem('accessToken', resp.data.data)
  } catch (e) {
    // get token failed
    fcl.unauthenticate();
    console.log("wallet connect failed...");
  }
};
onMounted(() => {
  fcl.currentUser.subscribe(setUser);
});
// sign a message
const sign = async (): Promise<any> => {
  // message must be a hex string
  const msg = Buffer.from("Welcome to LemonNeko's blog. " + Date.now()).toString("hex");
  const sig = await fcl.currentUser.signUserMessage(msg);
  return {
    msg,
    sig
  };
};
</script>

<template>
  <h1>{{ msg }}</h1>

  <div class="card">
    <p v-if="currentUser?.addr">current user: {{ currentUser.addr }}</p>
    <button v-if="currentUser?.addr" type="button" @click="fcl.unauthenticate">
      Logout
    </button>
    <button v-else type="button" @click="fcl.logIn">Login</button>
    <button v-if="currentUser?.addr" type="button" @click="getInfo">Get profile</button>
  </div>
</template>

<style scoped>
.read-the-docs {
  color: #888;
}
</style>
