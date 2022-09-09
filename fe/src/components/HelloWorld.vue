<script setup lang="ts">
import { onMounted, ref } from "vue";
import * as fcl from "@onflow/fcl";
import { Buffer } from "buffer";
import axios from "axios";

defineProps<{ msg: string }>();

const count = ref(0);
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
    if (resp.data.address === currentUser.value.addr) {
      // token is valid
      return resp.data;
    }
    return null;
  } catch (e) {
    return null;
  }
};
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
  console.log('get signature: ' + signature)
  if (!signature[1]) {
    // user rejected
    fcl.unauthenticate();
    console.log("wallet connect failed...");
    return;
  }
  console.log('signed a message.')
  // get a token
  try {
    const resp = await axios.post("http://localhost:3336/login", {
      address: currentUser.value.addr,
      message: signature[0],
      signature: signature[1],
    });
    localStorage.setItem('accessToken', resp.data)
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
  // const msg = Buffer.from("Welcome to LemonNeko's blog. 1662696806339").toString("hex");
  console.log(msg)
  const signedMsg = await fcl.currentUser.signUserMessage(msg);
  console.log(signedMsg)
  return [msg, signedMsg[0]?.signature];
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
    <button v-if="currentUser?.addr" type="button" @click="sign">Sign a message</button>
    <p>
      Edit
      <code>components/HelloWorld.vue</code> to test HMR
    </p>
  </div>

  <p>
    Check out
    <a href="https://vuejs.org/guide/quick-start.html#local" target="_blank">create-vue</a
    >, the official Vue + Vite starter
  </p>
  <p>
    Install
    <a href="https://github.com/johnsoncodehk/volar" target="_blank">Volar</a>
    in your IDE for a better DX
  </p>
  <p class="read-the-docs">Click on the Vite and Vue logos to learn more</p>
</template>

<style scoped>
.read-the-docs {
  color: #888;
}
</style>
