<template>
  <h1>Roles</h1>
</template>

<script>
import { onMounted } from 'vue';
import useRoles from '@/hooks/roles';

export default {
  name: 'Roles',
  setup() {
    const {fetchRoles} = useRoles();

    onMounted(() => {
      fetchRoles(0, 100, {name: 'name', order: 'ASC'});
    });
    return {};
  }
};
</script>

<style scoped>
</style>
