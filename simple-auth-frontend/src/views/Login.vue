<template>
  <section class="w3-container">
    <div class="w3-container">
      <h2>Login</h2>
    </div>
    <form class="w3-container" @submit.prevent="submitForm">
      <p>
        <label for="username" class="w3-text-teal">username</label>
        <input id="username" class="w3-input w3-border w3-light-grey" type="text" v-model.trim="username">
      </p>
      <p>
        <label for="password" class="w3-text-teal">password</label>
        <input id="password" class="w3-input w3-border w3-light-grey" type="password" v-model.trim="password">
      </p>
      <button class="w3-button w3-teal">Login</button>
      <div class="w3-container w3-text-red" v-if="!isFormValid">username or password is empty</div>
    </form>

    <w3-modal @click="clickModal" :show="showModal">
      <div class="w3-modal-content w3-card-4">
        <header class="w3-container w3-teal">
          <span @click="clickModal" class="w3-button w3-display-topright">&times;</span>
          <h2>Login error</h2>
        </header>
        <div class="w3-container">
          <p class="w3-text-red">{{ fetchMessage }}</p>
        </div>
      </div>
    </w3-modal>

    <w3-modal :show="fetch">
      <base-spinner></base-spinner>
    </w3-modal>
  </section>
</template>

<script>
import W3Modal from '@/components/ui/w3-modal';
import BaseSpinner from '@/components/ui/BaseSpinner';

import { computed, ref } from 'vue';
import useAuth from '@/hooks/auth';

export default {
  name: 'Login',
  components: {BaseSpinner, W3Modal},
  setup() {
    const {login, fetch, fetchMessage} = useAuth();

    const username = ref('');
    const password = ref('');
    const isFormValid = ref(true);

    const submitForm = () => {
      isFormValid.value = username.value !== '' && password.value !== '';
      if (!isFormValid.value) {
        return;
      }
      modalClosed.value = false;
      login(username.value, password.value);
    };

    const modalClosed = ref(false);

    const showModal = computed(() => {
      return !modalClosed.value && !!fetchMessage.value;
    });

    const clickModal = () => {
      modalClosed.value = true;
    };

    return {
      username,
      password,
      isFormValid,
      submitForm,
      fetch,
      fetchMessage,
      showModal,
      clickModal
    };
  }
}
</script>
