// const AUTHENTICATE_URL = '/api/authenticate';
// const CURRENT_USER_URL = '/api/current-user';

const EXPIRES_DELTA = 60;

let timer;

export default {
    initAuth(context) {
        console.log('initAuth');

        const token = localStorage.getItem('token');
        const expiresAt = localStorage.getItem('expiresAt');
        const currentUser = localStorage.getItem('currentUser');

        console.log(token);
        console.log(expiresAt);
        console.log(currentUser);

        if (token && expiresAt && currentUser) {
            clearTimeout(timer);
            const expiresIn = (expiresAt - new Date().getMilliseconds()) / 1000;
            if (expiresIn > EXPIRES_DELTA) {
                timer = setTimeout(() => {
                    context.dispatch('logout');
                }, expiresIn);
                context.commit('setAuth', {
                    token,
                    expiresAt,
                    currentUser
                });
            }
        }
    },
    login(context, payload) {
        console.log('login');
        console.log(payload);

        const fakeToken = 'fake token';
        const fakeExpiresAt = new Date().getMilliseconds() + 2 * EXPIRES_DELTA * 1000;
        const fakeCurrentUser = {
            id: 1,
            username: 'trevor.ochmonek.dev',
            enabled: true,
            roles: [
                {
                    id: 1,
                    name: 'view-users'
                },
                {
                    id: 3,
                    name: 'view-hotels'
                },
                {
                    id: 2,
                    name: 'manage-users'
                },
                {
                    id: 4,
                    name: 'manage-hotels'
                }
            ],
            attributes: {
                hotel_code: 'simple-123',
                given_name: 'Trevor',
                family_name: 'Ochmonek',
                email: 'trevor.ochmonek@melmac.com'
            }
        };

        localStorage.setItem('token', fakeToken);
        localStorage.setItem('expiresAt', fakeExpiresAt);
        localStorage.setItem('currentUser', fakeCurrentUser);

        clearTimeout(timer);
        const expiresIn = 2 * EXPIRES_DELTA * 1000;
        timer = setTimeout(() => {
            context.dispatch('logout');
        }, expiresIn);

        context.commit('setAuth', {
            token: fakeToken,
            expiresAt: fakeExpiresAt,
            currentUser: fakeCurrentUser
        });
    },
    logout(context) {
        console.log('logout');

        localStorage.removeItem('token');
        localStorage.removeItem('expiresAt');
        localStorage.removeItem('currentUser');

        clearTimeout(timer);

        context.commit('setAuth', {
            token: null,
            expiresAt: null,
            currentUser: null
        });
    }
};
