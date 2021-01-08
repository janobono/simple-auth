<template>
  <div class="w3-bar w3-border w3-light-grey">
    <router-link class="w3-bar-item w3-button w3-text-teal" to="/">Home</router-link>
    <router-link class="w3-bar-item w3-button" to="/roles" v-if="isLoggedIn">Roles</router-link>
    <router-link class="w3-bar-item w3-button" to="/users" v-if="isLoggedIn">Users</router-link>
    <router-link class="w3-bar-item w3-button" to="/login" v-if="!isLoggedIn">Login</router-link>
    <button class="w3-bar-item w3-button" v-if="isLoggedIn" @click="logout">Logout</button>
  </div>
</template>

<script>
import useAuth from "@/hooks/Auth";

export default {
  name: "TheNavigationBar",
  setup() {
    const {isLoggedIn, logout} = useAuth();
    return {isLoggedIn, logout};
  }
}
</script>
