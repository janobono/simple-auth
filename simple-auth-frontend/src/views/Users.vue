<template>
  <h1>Users</h1>

  <table class="w3-table">
    <tr class="w3-light-grey">
      <th>id</th>
      <th>username</th>
      <th>enabled</th>
      <th>roles</th>
      <th>attributes</th>
    </tr>
    <tr v-for="user in data" :key="user.id">
      <td>{{ user.id }}</td>
      <td>{{ user.username }}</td>
      <td>{{ user.enabled }}</td>
      <td>{{ user.roles }}</td>
      <td>{{ user.attributes }}</td>
    </tr>
  </table>

  <w3-modal @click="clickModal" :show="showModal">
    <div class="w3-modal-content w3-card-4">
      <header class="w3-container w3-teal">
        <span @click="clickModal" class="w3-button w3-display-topright">&times;</span>
        <h2>Fetch error</h2>
      </header>
      <div class="w3-container">
        <p class="w3-text-red">{{ fetchMessage }}</p>
      </div>
    </div>
  </w3-modal>

  <w3-modal :show="fetch">
    <base-spinner></base-spinner>
  </w3-modal>
</template>

<script>
import W3Modal from '@/components/ui/w3-modal';
import BaseSpinner from '@/components/ui/BaseSpinner';

import { computed, onMounted, ref } from 'vue';
import useUsers from '@/hooks/users';

export default {
  name: 'Users',
  components: {BaseSpinner, W3Modal},
  setup() {
    const {fetch, fetchMessage, fetchPage, page, data} = useUsers();

    const modalClosed = ref(false);

    const showModal = computed(() => {
      return !modalClosed.value && !!fetchMessage.value;
    });

    const clickModal = () => {
      modalClosed.value = true;
    };

    onMounted(() => {
      if (data.value.length === 0) {
        fetchPage(0, 100, {name: 'username', order: 'ASC'});
      }
    });

    return {fetch, fetchMessage, fetchPage, page, data, clickModal, showModal};
  }
};
</script>

<style scoped>
</style>
