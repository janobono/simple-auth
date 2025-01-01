import { useContext, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import AuthDefender from '../../component/layout/auth-defender';
import WiwaButton from '../../component/ui/wiwa-button';
import { AuthContext } from '../../context';

const SignOutPage = () => {
    const navigate = useNavigate();

    const authState = useContext(AuthContext);

    useEffect(() => {
        if (authState) {
            authState.signOut().then(() => navigate('/'));
        }
    }, [authState]);

    return (
        <AuthDefender>
            <div className="container p-2 mx-auto flex flex-row items-center justify-center">
                <WiwaButton
                    className="btn-primary"
                    disabled={authState?.busy}
                    onClick={() => authState?.signOut().then(() => navigate('/'))}
                >Sign Out</WiwaButton>
            </div>
        </AuthDefender>
    )
}

export default SignOutPage;
