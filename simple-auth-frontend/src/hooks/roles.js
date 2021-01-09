import axios from 'axios';
import { ref } from 'vue';
import store from '@/store';

const client = axios.create({baseURL: '/api/roles'});

export default function useRoles() {

    const fetch = ref(false);
    const fetchMessage = ref('');
    const page = ref(0);
    const size = ref(10);
    const totalPages = ref(0);

    const fetchRoles = () => {
        let config = {
            headers: {'Authorization': 'Bearer ' + store.getters.token},
            // params: {
            //     page: page,
            //     size: size,
            //     sort: sort.name + ',' + sort.order
            // }
        };
        console.log(config);

        fetch.value = true;
        fetchMessage.value = '';
        client.get('', config).then(response => {
            console.log(response);
        }).catch(error => {
            console.log(error);
            fetch.value = false;
            fetchMessage.value = error.message;
        });
    };

    return {fetch, fetchMessage, fetchRoles, page, size, totalPages};
}
