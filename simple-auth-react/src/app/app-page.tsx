import { Navigate, Route, Routes } from 'react-router-dom';

import AdminPage from './admin/admin-page';
import AdminUsersPage from './admin/users-page';

import AuthPage from './auth/auth-page';
import AuthChangeDetailsPage from './auth/change-details-page';
import AuthChangePasswordPage from './auth/change-password-page';
import AuthResetPasswordPage from './auth/reset-password-page';
import AuthSignInPage from './auth/sign-in-page';
import AuthSignOutPage from './auth/sign-out-page';
import AuthSignUpPage from './auth/sign-up-page';

import CustomerPage from './customer/customer-page';

import EmployeePage from './employee/employee-page';

import ManagerPage from './manager/manager-page';

import ConfirmPage from './confirm-page';

import HomePage from './home-page';

import NotFoundPage from './not-found-page';

const AppPage = () => {
    return (
        <Routes>
            <Route path="/" element={<HomePage/>}/>

            <Route path="/admin" element={<AdminPage/>}>
                <Route index element={<Navigate to="users" replace/>}/>
                <Route path="users" element={<AdminUsersPage/>}/>
            </Route>

            <Route path="/auth" element={<AuthPage/>}>
                <Route path="change-details" element={<AuthChangeDetailsPage/>}/>
                <Route path="change-password" element={<AuthChangePasswordPage/>}/>
                <Route path="reset-password" element={<AuthResetPasswordPage/>}/>
                <Route path="sign-in" element={<AuthSignInPage/>}/>
                <Route path="sign-out" element={<AuthSignOutPage/>}/>
                <Route path="sign-up" element={<AuthSignUpPage/>}/>
            </Route>

            <Route path="/customer" element={<CustomerPage/>}/>

            <Route path="/employee" element={<EmployeePage/>}/>

            <Route path="/manager" element={<ManagerPage/>}/>

            <Route path="/confirm/:token" element={<ConfirmPage/>}/>

            <Route path="*" element={<NotFoundPage/>}/>
        </Routes>
    )
}

export default AppPage;
