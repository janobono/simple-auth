export default {
    setAuth(state, payload) {
        state.token = payload.token;
        state.expiresAt = payload.expiresAt;
    }
};
