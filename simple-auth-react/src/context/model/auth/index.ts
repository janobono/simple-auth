import { ClientResponse } from '../../../api/controller';
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
} from '../../../api/model/data';

export interface AuthState {
    busy: boolean,
    accessToken?: string,
    user?: User,
    timeToAccessExpiration: number,
    adminAuthority: boolean,
    managerAuthority: boolean,
    employeeAuthority: boolean,
    customerAuthority: boolean,
    signIn: (signIn: SignIn) => Promise<ClientResponse<AuthenticationResponse>>,
    signOut: () => Promise<void>,
    signUp: (signUp: SignUp) => Promise<ClientResponse<AuthenticationResponse>>,
    confirm: (confirmation: Confirmation) => Promise<ClientResponse<AuthenticationResponse>>,
    resetPassword: (resetPassword: ResetPassword) => Promise<ClientResponse<void>>,
    changePassword: (changePassword: ChangePassword) => Promise<ClientResponse<AuthenticationResponse>>,
    changeEmail: (changeEmail: ChangeEmail) => Promise<ClientResponse<AuthenticationResponse>>,
    changeUserDetails: (changeUserDetails: ChangeUserDetails) => Promise<ClientResponse<AuthenticationResponse>>,
    loadAccessToken: () => string | undefined
}
