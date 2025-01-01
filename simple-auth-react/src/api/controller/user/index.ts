import {
    CONTEXT_PATH,
    deleteData,
    getData,
    patchData,
    postData,
    putData,
    setPageableQueryParams,
    setQueryParam
} from '../';
import { Pageable } from '../../model';
import { Authority, PageUser, User, UserCreate, UserProfile } from '../../model/data';

const PATH = CONTEXT_PATH + 'users';

export interface UserSearchCriteria {
    searchField?: string;
    username?: string;
    email?: string;
}

export const getUsers = (criteria?: UserSearchCriteria, pageable?: Pageable, accessToken?: string) => {
    const queryParams = new URLSearchParams();
    setPageableQueryParams(queryParams, pageable);
    if (criteria) {
        if (criteria.searchField) {
            setQueryParam(queryParams, 'searchField', criteria.searchField);
        }
        if (criteria.username) {
            setQueryParam(queryParams, 'username', criteria.username);
        }
        if (criteria.email) {
            setQueryParam(queryParams, 'email', criteria.email);
        }
    }
    return getData<PageUser>(PATH, queryParams, accessToken);
}

export const getUser = (id: number, accessToken?: string) => {
    return getData<User>(PATH + '/' + id, undefined, accessToken);
}

export const addUser = (userCreate: UserCreate, accessToken?: string) => {
    return postData<User>(PATH, userCreate, accessToken);
}

export const setUser = (id: number, userProfile: UserProfile, accessToken?: string) => {
    return putData<User>(PATH + '/' + id, userProfile, accessToken);
}

export const setAuthorities = (id: number, authorities: Authority[], accessToken?: string) => {
    return patchData<User>(PATH + '/' + id + '/authorities', authorities, accessToken);
}

export const setConfirmed = (id: number, confirmed: boolean, accessToken?: string) => {
    return patchData<User>(PATH + '/' + id + '/confirm', {value: confirmed}, accessToken);
}

export const setEnabled = (id: number, enabled: boolean, accessToken?: string) => {
    return patchData<User>(PATH + '/' + id + '/enable', {value: enabled}, accessToken);
}

export const deleteUser = (id: number, accessToken?: string) => {
    return deleteData<void>(PATH + '/' + id, accessToken);
}
