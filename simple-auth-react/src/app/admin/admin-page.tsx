import { Outlet } from 'react-router-dom';
import { Authority } from '../../api/model/data';

import AuthDefender from '../../component/layout/auth-defender';
import Footer from '../../component/layout/footer';
import Navigation from '../../component/layout/navigation';

const AdminPage = () => {
    return (
        <>
            <AuthDefender authority={Authority.ADMIN}>
                <Navigation/>
                <main className="flex-grow">
                    <div className="flex flex-col justify-start items-center w-full p-2 gap-2 bg-base">
                        <Outlet/>
                    </div>
                </main>
                <Footer/>
            </AuthDefender>
        </>
    )
}

export default AdminPage;
