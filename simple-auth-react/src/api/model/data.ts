/* tslint:disable */
/* eslint-disable */
/**
 * 
 * @export
 * @interface AuthenticationResponse
 */
export interface AuthenticationResponse {
    /**
     * 
     * @type {string}
     * @memberof AuthenticationResponse
     */
    token?: string;
    /**
     * 
     * @type {string}
     * @memberof AuthenticationResponse
     */
    type?: string;
}

/**
 * 
 * @export
 */
export const Authority = {
    ADMIN: 'admin',
    MANAGER: 'manager',
    EMPLOYEE: 'employee',
    CUSTOMER: 'customer'
} as const;
export type Authority = typeof Authority[keyof typeof Authority];

/**
 * 
 * @export
 * @interface BooleanValue
 */
export interface BooleanValue {
    /**
     * 
     * @type {boolean}
     * @memberof BooleanValue
     */
    value: boolean;
}
/**
 * 
 * @export
 * @interface Captcha
 */
export interface Captcha {
    /**
     * 
     * @type {string}
     * @memberof Captcha
     */
    captchaToken?: string;
    /**
     * 
     * @type {string}
     * @memberof Captcha
     */
    captchaImage?: string;
}
/**
 * 
 * @export
 * @interface ChangeEmail
 */
export interface ChangeEmail {
    /**
     * 
     * @type {string}
     * @memberof ChangeEmail
     */
    email: string;
    /**
     * 
     * @type {string}
     * @memberof ChangeEmail
     */
    password: string;
    /**
     * 
     * @type {string}
     * @memberof ChangeEmail
     */
    captchaText: string;
    /**
     * 
     * @type {string}
     * @memberof ChangeEmail
     */
    captchaToken: string;
}
/**
 * 
 * @export
 * @interface ChangePassword
 */
export interface ChangePassword {
    /**
     * 
     * @type {string}
     * @memberof ChangePassword
     */
    oldPassword: string;
    /**
     * 
     * @type {string}
     * @memberof ChangePassword
     */
    newPassword: string;
    /**
     * 
     * @type {string}
     * @memberof ChangePassword
     */
    captchaText: string;
    /**
     * 
     * @type {string}
     * @memberof ChangePassword
     */
    captchaToken: string;
}
/**
 * 
 * @export
 * @interface ChangeUserDetails
 */
export interface ChangeUserDetails {
    /**
     * 
     * @type {string}
     * @memberof ChangeUserDetails
     */
    firstName: string;
    /**
     * 
     * @type {string}
     * @memberof ChangeUserDetails
     */
    lastName: string;
    /**
     * 
     * @type {string}
     * @memberof ChangeUserDetails
     */
    captchaText: string;
    /**
     * 
     * @type {string}
     * @memberof ChangeUserDetails
     */
    captchaToken: string;
}
/**
 * 
 * @export
 * @interface Confirmation
 */
export interface Confirmation {
    /**
     * 
     * @type {string}
     * @memberof Confirmation
     */
    token: string;
}

/**
 * 
 * @export
 */
export const ErrorCode = {
    UNKNOWN: 'UNKNOWN',
    NOT_FOUND: 'NOT_FOUND',
    UNAUTHORIZED: 'UNAUTHORIZED',
    FORBIDDEN: 'FORBIDDEN',
    AUTHORITY_NOT_FOUND: 'AUTHORITY_NOT_FOUND',
    INVALID_CAPTCHA: 'INVALID_CAPTCHA',
    INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
    UNSUPPORTED_VALIDATION_TOKEN: 'UNSUPPORTED_VALIDATION_TOKEN',
    USER_EMAIL_IS_USED: 'USER_EMAIL_IS_USED',
    USER_NOT_CONFIRMED: 'USER_NOT_CONFIRMED',
    USER_IS_DISABLED: 'USER_IS_DISABLED',
    USER_NOT_FOUND: 'USER_NOT_FOUND'
} as const;
export type ErrorCode = typeof ErrorCode[keyof typeof ErrorCode];

/**
 * 
 * @export
 * @interface ErrorMessage
 */
export interface ErrorMessage {
    /**
     * 
     * @type {ErrorCode}
     * @memberof ErrorMessage
     */
    code?: ErrorCode;
    /**
     * 
     * @type {string}
     * @memberof ErrorMessage
     */
    message?: string;
    /**
     * 
     * @type {string}
     * @memberof ErrorMessage
     */
    timestamp?: string;
}


/**
 * 
 * @export
 * @interface HealthStatus
 */
export interface HealthStatus {
    /**
     * 
     * @type {string}
     * @memberof HealthStatus
     */
    status?: string;
}
/**
 * 
 * @export
 * @interface PageUser
 */
export interface PageUser {
    /**
     * 
     * @type {number}
     * @memberof PageUser
     */
    totalElements?: number;
    /**
     * 
     * @type {number}
     * @memberof PageUser
     */
    totalPages?: number;
    /**
     * 
     * @type {boolean}
     * @memberof PageUser
     */
    first?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof PageUser
     */
    last?: boolean;
    /**
     * 
     * @type {number}
     * @memberof PageUser
     */
    page?: number;
    /**
     * 
     * @type {number}
     * @memberof PageUser
     */
    size?: number;
    /**
     * 
     * @type {Array<User>}
     * @memberof PageUser
     */
    content?: Array<User>;
    /**
     * 
     * @type {boolean}
     * @memberof PageUser
     */
    empty?: boolean;
}
/**
 * 
 * @export
 * @interface ResetPassword
 */
export interface ResetPassword {
    /**
     * 
     * @type {string}
     * @memberof ResetPassword
     */
    email: string;
    /**
     * 
     * @type {string}
     * @memberof ResetPassword
     */
    captchaText: string;
    /**
     * 
     * @type {string}
     * @memberof ResetPassword
     */
    captchaToken: string;
}
/**
 * 
 * @export
 * @interface SignIn
 */
export interface SignIn {
    /**
     * 
     * @type {string}
     * @memberof SignIn
     */
    email: string;
    /**
     * 
     * @type {string}
     * @memberof SignIn
     */
    password: string;
}
/**
 * 
 * @export
 * @interface SignUp
 */
export interface SignUp {
    /**
     * 
     * @type {string}
     * @memberof SignUp
     */
    email: string;
    /**
     * 
     * @type {string}
     * @memberof SignUp
     */
    password: string;
    /**
     * 
     * @type {string}
     * @memberof SignUp
     */
    firstName: string;
    /**
     * 
     * @type {string}
     * @memberof SignUp
     */
    lastName: string;
    /**
     * 
     * @type {string}
     * @memberof SignUp
     */
    captchaText: string;
    /**
     * 
     * @type {string}
     * @memberof SignUp
     */
    captchaToken: string;
}
/**
 * 
 * @export
 * @interface User
 */
export interface User {
    /**
     * 
     * @type {number}
     * @memberof User
     */
    id?: number;
    /**
     * 
     * @type {string}
     * @memberof User
     */
    email?: string;
    /**
     * 
     * @type {string}
     * @memberof User
     */
    firstName?: string;
    /**
     * 
     * @type {string}
     * @memberof User
     */
    lastName?: string;
    /**
     * 
     * @type {boolean}
     * @memberof User
     */
    confirmed?: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof User
     */
    enabled?: boolean;
    /**
     * 
     * @type {Array<Authority>}
     * @memberof User
     */
    authorities?: Array<Authority>;
}
/**
 * 
 * @export
 * @interface UserCreate
 */
export interface UserCreate {
    /**
     * 
     * @type {string}
     * @memberof UserCreate
     */
    email: string;
    /**
     * 
     * @type {string}
     * @memberof UserCreate
     */
    firstName: string;
    /**
     * 
     * @type {string}
     * @memberof UserCreate
     */
    lastName: string;
    /**
     * 
     * @type {boolean}
     * @memberof UserCreate
     */
    confirmed: boolean;
    /**
     * 
     * @type {boolean}
     * @memberof UserCreate
     */
    enabled: boolean;
    /**
     * 
     * @type {Array<Authority>}
     * @memberof UserCreate
     */
    authorities?: Array<Authority>;
}
/**
 * 
 * @export
 * @interface UserProfile
 */
export interface UserProfile {
    /**
     * 
     * @type {string}
     * @memberof UserProfile
     */
    firstName: string;
    /**
     * 
     * @type {string}
     * @memberof UserProfile
     */
    lastName: string;
}
