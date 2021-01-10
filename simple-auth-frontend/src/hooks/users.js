import { computed } from 'vue';
import useFetch from '@/hooks/fetch';
import store from '@/store';

export default function useUsers() {

    const {fetch, fetchMessage, page, fetchPage} = useFetch('/api/users', 'user/setUsers');

    const data = computed(() => {
        return store.getters['user/users'];
    });

    return {fetch, fetchMessage, fetchPage, page, data};
}
