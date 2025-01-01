import { Captcha } from '../../model/data';
import { CONTEXT_PATH, getData } from '../index';

export const getCaptcha = () => {
    return getData<Captcha>(CONTEXT_PATH + 'captcha');
}
