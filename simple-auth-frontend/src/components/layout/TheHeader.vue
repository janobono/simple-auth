<template>
  <header class="w3-container w3-teal">
    <div class="w3-row">
      <router-link class="w3-wide" to="/"><h1>Simple Auth</h1></router-link>
    </div>
    <div class="w3-row">
      <div class="w3-bar">
        <div class="w3-right">
          <router-link class="w3-bar-item w3-button" to="/roles" v-if="isLoggedIn">Roles</router-link>
          <router-link class="w3-bar-item w3-button" to="/users" v-if="isLoggedIn">Users</router-link>
          <router-link class="w3-bar-item w3-button" to="/login" v-if="!isLoggedIn">Login</router-link>
          <button class="w3-button w3-black" v-if="isLoggedIn" @click="logout">Logout</button>
        </div>
      </div>
    </div>
  </header>
</template>

<script>
import { useStore } from 'vuex';
import { useRouter } from 'vue-router';
import useAuth from "@/hooks/Auth";

export default {
  name: "TheHeader",
  setup() {
    const {isToken} = useAuth();
    const store = useStore();
    const router = useRouter();
    const logout = () => {
      store.dispatch('logout');
      router.replace('/');
    };
    return {isLoggedIn: isToken, logout};
  }
}
</script>

<style scoped>

</style>
