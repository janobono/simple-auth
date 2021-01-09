import axios from 'axios';
import { computed, ref } from 'vue';
import store from '@/store';
import router from '@/router';

const client = axios.create({baseURL: '/api'});

export default function useAuth() {
    const isLoggedIn = computed(() => {
        return !!store.getters.token;
    });

    const initAuth = () => {
        store.dispatch('initAuth');
    };

    const fetch = ref(false);
    const fetchMessage = ref('');

    const login = (username, password) => {
        fetch.value = true;
        fetchMessage.value = '';
        client.post('/authenticate', {username, password}).then(response => {
            store.dispatch('login', response.data);
            router.replace('/');
        }).catch(error => {
            let message = error.message;
            if (error.response.status === 400) {
                message = 'Wrong username or password!';
            }
            fetch.value = false;
            fetchMessage.value = message;
        });
    };

    const logout = () => {
        store.dispatch('logout');
        router.replace('/');
    }
    return {isLoggedIn, initAuth, login, logout, fetch, fetchMessage};
}
