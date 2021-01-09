import { createStore } from 'vuex';
import auth from './auth';
import role from './role';
import user from './user';

const store = createStore({
    modules: {
        auth,
        role,
        user
    }
});

export default store;
