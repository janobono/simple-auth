<template>
  <div class="w3-container">
    <p>Really simple and ugly frontend.</p>
    <p v-if="!isLoggedIn">Login to start work.</p>
  </div>
</template>

<script>
import useAuth from "@/hooks/Auth";

export default {
  name: "Home",
  setup() {
    const {isToken} = useAuth();
    return {isLoggedIn: isToken};
  }
}
</script>
