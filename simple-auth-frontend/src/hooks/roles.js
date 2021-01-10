import { computed } from 'vue';
import useFetch from '@/hooks/fetch';
import store from '@/store';

export default function useRoles() {

    const {fetch, fetchMessage, page, fetchPage} = useFetch('/api/roles', 'role/setRoles');

    const data = computed(() => {
        return store.getters['role/roles'];
    });

    return {fetch, fetchMessage, fetchPage, page, data};
}
