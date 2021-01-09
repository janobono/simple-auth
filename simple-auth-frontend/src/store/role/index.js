import getters from './getters';
import mutations from './mutations';

export default {
    namespaced: true,
    state() {
        return {
            roles: []
        };
    },
    getters,
    mutations
};
