import { createRouter, createWebHistory } from 'vue-router';
import store from '@/store';

import HomeComponent from '@/views/Home';
import LoginComponent from '@/views/Login';
import NotFoundComponent from '@/views/NotFound';

const component = {
    roles: () => import(/* webpackChunkName: "lazy-components" */ '@/views/Roles'),
    users: () => import(/* webpackChunkName: "lazy-components" */ '@/views/Users')
};

const routes = [
    {path: '/', component: HomeComponent},
    {path: '/login', component: LoginComponent},
    {path: '/roles', meta: {requiresAuth: true}, component: component.roles},
    {path: '/users', meta: {requiresAuth: true}, component: component.users},
    {path: '/:NotFound(.*)', component: NotFoundComponent}
];

const router = createRouter({
    history: createWebHistory(process.env.BASE_URL),
    routes
});

router.beforeEach((to, from, next) => {
    if (to.meta.requiresAuth && !store.getters.token) {
        next('/login');
    } else {
        next();
    }
});

export default router;
