import getters from "./getters";
import mutations from "./mutations";
import actions from "./actions";

export default {
    state() {
        return {
            token: null,
            expiresAt: null
        };
    },
    getters,
    mutations,
    actions
};
