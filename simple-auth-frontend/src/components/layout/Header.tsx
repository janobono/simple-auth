import React, { FunctionComponent, useContext } from 'react';
import { useNavigate } from 'react-router';
import { FaHome } from 'react-icons/fa';
import {
    Box,
    Button,
    ButtonGroup,
    Container,
    Flex,
    Heading,
    HStack,
    Icon,
    IconButton,
    Spacer,
    Stack,
    Text
} from '@chakra-ui/react';
import { useTranslation } from 'react-i18next';

import ColorModeSwitcher from '../ColorModeSwitcher';
import AuthContext from '../../contexts/auth-context';
import LocaleSwitcher from '../LocaleSwitcher';

const Header: FunctionComponent = () => {
    const navigate = useNavigate();
    const authCtx = useContext(AuthContext);
    const {t} = useTranslation();

    return (
        <header>
            <Container maxW="container.sm" marginBottom="10">
                <Flex>
                    <Box p="2">
                        <HStack>
                            <IconButton
                                colorScheme="teal"
                                aria-label="Home"
                                icon={<Icon as={FaHome}/>}
                                onClick={() => navigate('/')}
                            />
                            <Heading size="lg">{t('title')}</Heading>
                        </HStack>
                    </Box>
                    <Spacer/>
                    <Box pt="2">
                        <ButtonGroup mr="4">
                            {authCtx.payload ?
                                <Button colorScheme="teal" variant="outline" onClick={() => {
                                    authCtx.onLogout();
                                    navigate('/');
                                }}>{t('header.log-out')}</Button>
                                : <React.Fragment>
                                    <Button colorScheme="teal" variant="solid" onClick={() => navigate('/sign-up')}>
                                        {t('header.sign-up')}
                                    </Button>
                                    <Button colorScheme="teal" variant="outline" onClick={() => navigate('/log-in')}>
                                        {t('header.log-in')}
                                    </Button>
                                </React.Fragment>
                            }
                            <ColorModeSwitcher justifySelf="flex-end"/>
                            <LocaleSwitcher/>
                        </ButtonGroup>
                    </Box>
                </Flex>
                {authCtx.payload &&
                    <Stack>
                        <Text>Welcome dear
                            user <strong>{authCtx.payload.username} {authCtx.payload.iat}</strong></Text>
                    </Stack>
                }
            </Container>
        </header>
    );
}

export default Header;
