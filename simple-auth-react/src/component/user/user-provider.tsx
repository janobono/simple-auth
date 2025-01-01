import { createContext, ReactNode, useContext, useEffect, useState } from 'react';

import { ClientResponse } from '../../api/controller';
import * as apiUser from '../../api/controller/user';
import { UserSearchCriteria } from '../../api/controller/user';
import { Authority, User } from '../../api/model/data';
import { AuthContext, ErrorContext } from '../../context';

export interface UserState {
    busy: boolean,
    isEditEnabled: (user: User) => boolean,
    previous: boolean,
    next: boolean,
    page: number,
    setPage: (page: number) => void,
    setCriteria: (criteria?: UserSearchCriteria) => void,
    data?: User[],
    getUsers: () => Promise<void>,
    setAuthorities: (id: number, authorities: Authority[]) => Promise<void>,
    setEnabled: (id: number, enabled: boolean) => Promise<void>,
    setConfirmed: (id: number, confirmed: boolean) => Promise<void>,
    deleteUser: (id: number) => Promise<void>
}

export const UserContext = createContext<UserState | undefined>(undefined);

const UserProvider = ({children}: { children: ReactNode }) => {
    const authState = useContext(AuthContext);
    const errorState = useContext(ErrorContext);

    const [busy, setBusy] = useState(false);
    const [previous, setPrevious] = useState(false);
    const [next, setNext] = useState(false);
    const [page, setPage] = useState(0);
    const [criteria, setCriteria] = useState<UserSearchCriteria>();
    const [data, setData] = useState<User[]>();

    useEffect(() => {
        if (authState?.accessToken) {
            getUsers().then();
        }
    }, [criteria, page]);

    const createData = (): User[] => {
        if (data) {
            return [...data];
        }
        return [];
    }

    const handleResponse = (response: ClientResponse<User>) => {
        if (response?.data) {
            const newData = createData();
            const index = newData.findIndex(item => item.id === response.data?.id);
            if (index !== -1) {
                newData[index] = response.data;
            }
            setData(newData);
        }
    }

    const isEditEnabled = (user: User) => user.id !== authState?.user?.id;

    const getUsers = async () => {
        setBusy(true);
        try {
            if (authState?.accessToken) {
                const response = await apiUser.getUsers(criteria, {
                    page,
                    size: 10,
                    sort: {field: 'id', asc: true}
                }, authState?.accessToken);
                setPrevious(!response.data?.first || false);
                setNext(!response.data?.last || false);
                setData(response.data?.content);
                errorState?.addError(response.error);
            }
        } finally {
            setBusy(false);
        }
    }

    const setAuthorities = async (id: number, authorities: Authority[]) => {
        setBusy(true);
        try {
            const response = await apiUser.setAuthorities(id, authorities, authState?.accessToken);
            handleResponse(response);
            errorState?.addError(response?.error);
        } finally {
            setBusy(false);
        }
    }

    const setEnabled = async (id: number, enabled: boolean) => {
        setBusy(true);
        try {
            const response = await apiUser.setEnabled(id, enabled, authState?.accessToken);
            handleResponse(response);
            errorState?.addError(response?.error);
        } finally {
            setBusy(false);
        }
    }

    const setConfirmed = async (id: number, confirmed: boolean) => {
        setBusy(true);
        try {
            const response = await apiUser.setConfirmed(id, confirmed, authState?.accessToken);
            handleResponse(response);
            errorState?.addError(response?.error);
        } finally {
            setBusy(false);
        }
    }

    const deleteUser = async (id: number) => {
        setBusy(true);
        try {
            const response = await apiUser.deleteUser(id, authState?.accessToken);
            if (!response.error) {
                const newData = createData();
                const index = newData.findIndex(item => item.id === id);
                if (index !== -1) {
                    newData.splice(index, 1);
                }
                setData(newData);
            }
            errorState?.addError(response?.error);
        } finally {
            setBusy(false);
        }
    }

    return (
        <UserContext.Provider
            value={
                {
                    busy,
                    isEditEnabled,
                    previous,
                    next,
                    page,
                    setPage,
                    setCriteria,
                    data,
                    getUsers,
                    setAuthorities,
                    setEnabled,
                    setConfirmed,
                    deleteUser
                }
            }
        >{children}
        </UserContext.Provider>
    )
}

export default UserProvider;
