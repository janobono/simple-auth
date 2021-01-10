import axios from 'axios';
import { reactive, ref } from 'vue';
import store from '@/store';

export default function useFetch(baseURL, mutation) {

    const client = axios.create({baseURL});

    const fetch = ref(false);
    const fetchMessage = ref('');
    const page = reactive({
        totalElements: 0,
        totalPages: 0,
        number: 0,
        first: true,
        numberOfElements: 0,
        last: true,
        size: 0,
        empty: true
    });

    const fetchPage = (pageNumber, pageSize, pageSort) => {
        let config = {
            headers: {'Authorization': 'Bearer ' + store.getters.token},
            params: {
                page: pageNumber,
                size: pageSize,
                sort: pageSort.name + ',' + pageSort.order
            }
        };
        fetch.value = true;
        fetchMessage.value = '';
        client.get('', config).then(response => {
            page.totalElements = response.data.totalElements;
            page.totalPages = response.data.totalPages;
            page.number = response.data.number;
            page.first = response.data.first;
            page.numberOfElements = response.data.numberOfElements;
            page.last = response.data.last;
            page.size = response.data.size;
            page.empty = response.data.empty;
            store.commit(mutation, response.data.content);
            fetch.value = false;
            fetchMessage.value = '';
        }).catch(error => {
            page.totalElements = 0;
            page.totalPages = 0;
            page.number = 0;
            page.first = true;
            page.numberOfElements = 0;
            page.last = true;
            page.size = 0;
            page.empty = true;
            store.commit(mutation, []);
            fetch.value = false;
            fetchMessage.value = error.message;
        });
    };

    return {fetch, fetchMessage, page, fetchPage};
}
