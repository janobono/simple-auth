import { ErrorMessage } from '../../../api/model/data';

export interface ErrorState {
    data: ErrorMessage[],
    addError: (error?: ErrorMessage) => void,
    removeError: (index: number) => void
}
