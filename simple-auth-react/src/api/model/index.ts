import { Authority } from './data';

export const containsAuthority = (authorities: Authority[], authority: Authority) => {
    return authorities.some(a => a === authority);
};

export interface Pageable {
    page: number,
    size: number,
    sort?: {
        field: string,
        asc: boolean
    }
}
