export default {
    isToken(state) {
        return !!state.token;
    },
    token(state) {
        return state.token;
    },
    expiresAt(state) {
        return state.expiresAt;
    },
    currentUser(state) {
        return state.currentUser;
    }
};
