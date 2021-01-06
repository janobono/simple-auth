<template>
  <h1>Login</h1>
  <button @click="submitForm" v-if="!isLoggedIn">Login</button>
</template>

<script>
import { useStore } from 'vuex';
import { useRouter } from 'vue-router';
import useAuth from "@/hooks/Auth";

export default {
  name: "Login",
  setup() {
    const {isToken} = useAuth();

    const store = useStore();
    const router = useRouter();

    const submitForm = () => {
      store.dispatch('login', {username: 'fake', password: 'fake'});
      router.replace('/roles');
    };

    return {isLoggedIn: isToken, submitForm};
  }
}
</script>

<style scoped>
</style>
