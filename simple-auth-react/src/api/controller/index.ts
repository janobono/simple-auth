/* tslint:disable */
/* eslint-disable */
import { Pageable } from '../model';
import { ErrorCode, ErrorMessage } from '../model/data';

export const CONTEXT_PATH = '/api/'

export const errorMessage = (message: string): ErrorMessage => {
    return {code: ErrorCode.UNKNOWN, message, timestamp: ''}
}

export interface ClientResponse<T> {
    data: T | undefined,
    error: ErrorMessage | undefined
}

export const toErrorMessage = async (response: Response): Promise<ErrorMessage> => {
    const result = errorMessage('Unknown exception');
    try {
        const data = await response.json();
        if (data && 'code' in data && 'message' in data && 'timestamp' in data) {
            const {code, message, timestamp} = data;
            result.code = code as ErrorCode;
            result.message = message;
            result.timestamp = timestamp;
        }
    } catch (error) {
        console.log(error);
    }
    return result;
}

export const setQueryParam = (queryParams: URLSearchParams, name: string, value?: any) => {
    if (value) {
        queryParams.set(name, `${value}`);
    }
}

export const setPageableQueryParams = (queryParams: URLSearchParams, pageable?: Pageable) => {
    if (pageable) {
        setQueryParam(queryParams, 'page', pageable.page);
        setQueryParam(queryParams, 'size', pageable.size);
        if (pageable.sort) {
            setQueryParam(queryParams, 'sort', `${pageable.sort.field},${pageable.sort.asc ? 'ASC' : 'DESC'}`);
        }
    }
}

export const createAuthorization = (token?: string): any => {
    if (token) {
        return {
            'Authorization': `Bearer ${token}`
        };
    } else {
        return {};
    }
}

export const getData = async <T>(path: string, queryParams?: URLSearchParams, token?: string): Promise<ClientResponse<T>> => {
    const authorization = createAuthorization(token);
    const response = await fetch(path + (queryParams ? '?' + queryParams.toString() : ''), {
        method: 'GET',
        headers: {
            ...authorization,
            'Content-Type': 'application/json'
        }
    });

    let data, error;
    if (response.ok) {
        const text = await response.text();
        if (text.length > 0) {
            data = await JSON.parse(text) as T;
        }
    } else {
        error = await toErrorMessage(response);
    }
    return {data, error};
}

export const postData = async <T>(path: string, data: any, token?: string): Promise<ClientResponse<T>> => {
    const authorization = createAuthorization(token);
    const response = await fetch(path, {
        method: 'POST',
        headers: {
            ...authorization,
            'Content-Type': 'application/json'
        },
        body: data ? JSON.stringify(data) : data
    });

    let resultData, error;
    if (response.ok) {
        const text = await response.text();
        if (text.length > 0) {
            resultData = await JSON.parse(text) as T;
        }
    } else {
        error = await toErrorMessage(response);
    }
    return {data: resultData, error};
}

export const putData = async <T>(path: string, data: any, token?: string): Promise<ClientResponse<T>> => {
    const authorization = createAuthorization(token);
    const response = await fetch(path, {
        method: 'PUT',
        headers: {
            ...authorization,
            'Content-Type': 'application/json'
        },
        body: data ? JSON.stringify(data) : data
    });

    let resultData, error;
    if (response.ok) {
        const text = await response.text();
        if (text.length > 0) {
            resultData = await JSON.parse(text) as T;
        }
    } else {
        error = await toErrorMessage(response);
    }
    return {data: resultData, error};
}

export const patchData = async <T>(path: string, data: any, token?: string): Promise<ClientResponse<T>> => {
    const authorization = createAuthorization(token);
    const response = await fetch(path, {
        method: 'PATCH',
        headers: {
            ...authorization,
            'Content-Type': 'application/json'
        },
        body: data ? JSON.stringify(data) : data
    });

    let resultData, error;
    if (response.ok) {
        const text = await response.text();
        if (text.length > 0) {
            resultData = await JSON.parse(text) as T;
        }
    } else {
        error = await toErrorMessage(response);
    }
    return {data: resultData, error};
}

export const deleteData = async <T>(path: string, token?: string): Promise<ClientResponse<T>> => {
    const authorization = createAuthorization(token);
    const response = await fetch(path, {
        method: 'DELETE',
        headers: authorization
    });

    let resultData, error;
    if (response.ok) {
        const text = await response.text();
        if (text.length > 0) {
            resultData = await JSON.parse(text) as T;
        }
    } else {
        error = await toErrorMessage(response);
    }
    return {data: resultData, error};
}

export const postFile = async <T>(path: string, file: File, token?: string): Promise<ClientResponse<T>> => {
    const authorization = createAuthorization(token);

    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(path, {
        method: 'POST',
        body: formData,
        headers: {
            ...authorization
        },
    });

    let resultData, error;
    if (response.ok) {
        const text = await response.text();
        if (text.length > 0) {
            resultData = await JSON.parse(text) as T;
        }
    } else {
        error = await toErrorMessage(response);
    }
    return {data: resultData, error};
}
