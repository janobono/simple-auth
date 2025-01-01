import { Outlet } from 'react-router-dom';
import Footer from '../../component/layout/footer';
import Navigation from '../../component/layout/navigation';

const AuthPage = () => {
    return (
        <>
            <Navigation/>
            <main className="flex-grow">
                <div
                    className="flex flex-col justify-start items-center w-full p-2 gap-2 bg-base">
                    <Outlet/>
                </div>
            </main>
            <Footer/>
        </>
    )
}

export default AuthPage;
