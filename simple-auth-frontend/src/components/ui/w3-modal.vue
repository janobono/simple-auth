<template>
  <teleport to="body">
    <div class="w3-container">
      <div class="w3-modal" :style="{'display':'block'}" v-if="show" @click="click">
        <slot></slot>
      </div>
    </div>
  </teleport>
</template>

<script>
export default {
  name: 'w3-modal',
  props: {
    show: {
      type: Boolean,
      required: true,
    }
  },
  emits: ['click'],
  methods: {
    click() {
      this.$emit('click');
    },
  },
};
</script>
