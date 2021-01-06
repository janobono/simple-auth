import { computed } from 'vue';
import { useStore } from 'vuex';

export default function useAuth() {
    const store = useStore();
    const isToken = computed(() => {
        return store.getters.isToken;
    });
    return {isToken};
}
