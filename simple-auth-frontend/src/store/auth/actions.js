const EXPIRES_DELTA = 60;

let timer;

export default {
    initAuth(context) {
        const token = localStorage.getItem('token');
        const expiresAt = localStorage.getItem('expiresAt');
        if (token && expiresAt) {
            const expiresIn = expiresAt - Date.now();
            clearTimeout(timer);
            if (expiresIn / 1000 > EXPIRES_DELTA) {
                timer = setTimeout(() => {
                    context.dispatch('logout');
                }, expiresIn);
                context.commit('setAuth', {token, expiresAt});
            }
        }
    },
    login(context, payload) {
        localStorage.setItem('token', payload.token);
        localStorage.setItem('expiresAt', payload.expiresAt);
        const expiresIn = payload.expiresAt - Date.now();
        clearTimeout(timer);
        timer = setTimeout(() => {
            context.dispatch('logout');
        }, expiresIn);
        context.commit('setAuth', {token: payload.token, expiresAt: payload.expiresAt});
    },
    logout(context) {
        localStorage.removeItem('token');
        localStorage.removeItem('expiresAt');
        clearTimeout(timer);
        context.commit('setAuth', {token: null, expiresAt: null});
    }
};
