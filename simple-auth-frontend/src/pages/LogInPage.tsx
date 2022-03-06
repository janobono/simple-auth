import { FunctionComponent } from 'react';
import { FieldValues, useForm } from 'react-hook-form'
import { Button, FormControl, FormErrorMessage, FormLabel, Input, } from '@chakra-ui/react'
import { useTranslation } from 'react-i18next';

const LogInPage: FunctionComponent = () => {
    const {t} = useTranslation();

    const {
        handleSubmit,
        register,
        formState: {errors, isSubmitting},
    } = useForm();

    const onSubmit = async (values: FieldValues) => {
        alert(JSON.stringify(values, null, 2));
    }

    return (
        <form onSubmit={handleSubmit(onSubmit)}>
            <FormControl isInvalid={errors.username}>
                <FormLabel htmlFor="username">{t('logIn.username.label')}</FormLabel>
                <Input
                    type="text"
                    id="username"
                    placeholder={t('logIn.username.label')}
                    {...register('username', {
                        required: t('logIn.username.required').trim()
                    })}
                />
                <FormErrorMessage>
                    {errors.username && errors.username.message}
                </FormErrorMessage>
            </FormControl>

            <FormControl isInvalid={errors.password}>
                <FormLabel htmlFor="password">{t('logIn.password.label')}</FormLabel>
                <Input
                    type="password"
                    id="password"
                    placeholder={t('logIn.password.label')}
                    {...register('password', {
                        required: t('logIn.password.required').trim()
                    })}
                />
                <FormErrorMessage>
                    {errors.password && errors.password.message}
                </FormErrorMessage>
            </FormControl>

            <Button mt={4} isLoading={isSubmitting} type="submit">
                {t('logIn.submit')}
            </Button>
        </form>
    );
}

export default LogInPage;
