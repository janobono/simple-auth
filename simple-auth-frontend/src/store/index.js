import { createStore } from 'vuex';
import auth from './auth';
import role from './role';
import user from './user';

export default createStore({
    modules: {
        auth,
        role,
        user
    }
});
