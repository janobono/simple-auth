import { CONTEXT_PATH, getData, postData } from '../';
import {
    AuthenticationResponse,
    ChangeEmail,
    ChangePassword,
    ChangeUserDetails,
    Confirmation,
    ResetPassword,
    SignIn,
    SignUp,
    User
} from '../../model/data';

const PATH = CONTEXT_PATH + 'auth';

export const confirm = (confirmation: Confirmation) => {
    return postData<AuthenticationResponse>(PATH + '/confirm', confirmation);
}

export const changeEmail = (changeEmail: ChangeEmail, accessToken?: string) => {
    return postData<AuthenticationResponse>(PATH + '/change-email', changeEmail, accessToken);
}

export const changePassword = (changePassword: ChangePassword, accessToken?: string) => {
    return postData<AuthenticationResponse>(PATH + '/change-password', changePassword, accessToken);
}

export const changeUserDetails = (changeUserDetails: ChangeUserDetails, accessToken?: string) => {
    return postData<AuthenticationResponse>(PATH + '/change-user-details', changeUserDetails, accessToken);
}

export const resetPassword = (resetPassword: ResetPassword) => {
    return postData<void>(PATH + '/reset-password', resetPassword);
}

export const signIn = (signIn: SignIn) => {
    return postData<AuthenticationResponse>(PATH + '/sign-in', signIn);
}

export const signUp = (signUp: SignUp) => {
    return postData<AuthenticationResponse>(PATH + '/sign-up', signUp);
}

export const getUserDetail = (accessToken?: string) => {
    return getData<User>(PATH + '/user-detail', undefined, accessToken);
}
