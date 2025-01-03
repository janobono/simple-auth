import { Authority } from '../../api/model/data';

import AuthDefender from '../../component/layout/auth-defender';
import Footer from '../../component/layout/footer';
import Navigation from '../../component/layout/navigation';

const EmployeePage = () => {
    return (
        <AuthDefender authority={Authority.EMPLOYEE}>
            <Navigation/>
            <main className="flex-grow">
                <div
                    className="flex flex-col justify-start items-center w-full p-2 gap-2 bg-base">
                    <h1>Employee Page</h1>
                </div>
            </main>
            <Footer/>
        </AuthDefender>
    )
}

export default EmployeePage;