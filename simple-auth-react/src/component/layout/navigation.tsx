import { useContext, useState } from 'react';
import { LogIn, PieChart, Settings, ShoppingCart, Tool, User } from 'react-feather';
import { NavLink } from 'react-router-dom';
import { AuthContext } from '../../context';
import WiwaMenuItem from '../ui/wiwa-menu-item';

const Navigation = () => {
    const authState = useContext(AuthContext);

    return (
        <nav className="flex flex-col w-full">
            <div className="flex flex-row justify-start items-center w-full bg-base-300 p-2">

                <img
                    className="object-scale-down object-center w-12 xl:w-16 h-12 xl:h-16"
                    src="/logo.webp"
                    alt="Logo"
                />

                <div className="flex flex-row items-center justify-center pl-2">
                    <NavLink
                        className="btn btn-ghost normal-case text-base font-bold"
                        to="/"
                    >Simple Auth React</NavLink>
                </div>

                <div className="grow"/>

                <div className="flex flex-col md:flex-row items-center justify-center">
                    {authState?.adminAuthority && <AdminNav/>}
                    {authState?.managerAuthority && <ManagerNav/>}
                    {authState?.employeeAuthority && <EmployeeNav/>}
                    {authState?.customerAuthority && <CustomerNav/>}
                    <AuthNav/>
                </div>
            </div>
        </nav>
    )
}

export default Navigation;

const AuthNav = () => {
    const authState = useContext(AuthContext);

    const [menuDisplay, setMenuDisplay] = useState(true);
    const [displayMenuStyle, setDisplayMenuStyle] = useState('');

    const showMenu = () => {
        setMenuDisplay(!menuDisplay)
        if (menuDisplay) {
            setDisplayMenuStyle('')
        } else {
            setDisplayMenuStyle('none')
        }
    }

    return (
        <div className="dropdown dropdown-end" onClick={showMenu}>
            <label
                tabIndex={0}
                className="btn btn-ghost btn-circle"
                title={authState?.timeToAccessExpiration !== 0 ? 'User' : 'Sign In'}
            >
                {authState?.timeToAccessExpiration !== 0 ? <User size="24"/> : <LogIn size="24"/>}
            </label>
            <ul tabIndex={0}
                style={{display: displayMenuStyle}}
                className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-44">
                {authState?.timeToAccessExpiration === 0 &&
                    <>
                        <WiwaMenuItem
                            label="Sign In"
                            to="/auth/sign-in"
                        />
                        <WiwaMenuItem
                            label="Sign Up"
                            to="/auth/sign-up"
                        />
                    </>
                }
                {authState?.timeToAccessExpiration !== 0 &&
                    <>
                        {authState?.customerAuthority &&
                            <>
                                <WiwaMenuItem
                                    label="Account details"
                                    to="/auth/change-details"
                                />
                                <WiwaMenuItem
                                    label="Change password"
                                    to="/auth/change-password"
                                />
                            </>
                        }
                        <WiwaMenuItem
                            label="Sign Out"
                            to="/auth/sign-out"
                        />
                    </>
                }
            </ul>
        </div>
    )
}

const AdminNav = () => {

    const [menuDisplay, setMenuDisplay] = useState(true);
    const [displayMenuStyle, setDisplayMenuStyle] = useState('');

    const showMenu = () => {
        setMenuDisplay(!menuDisplay)
        if (menuDisplay) {
            setDisplayMenuStyle('')
        } else {
            setDisplayMenuStyle('none')
        }
    }

    return (
        <div className="dropdown dropdown-end" onClick={showMenu}>
            <label
                tabIndex={0}
                className="btn btn-ghost btn-circle"
                title="Admin"
            >
                <Settings size="24"/>
            </label>
            <ul tabIndex={0}
                style={{display: displayMenuStyle}}
                className="menu menu-sm dropdown-content mt-3 z-[1] p-2 shadow bg-base-100 rounded-box w-44">
                <WiwaMenuItem
                    label="Users"
                    to="/admin/users"
                />
            </ul>
        </div>
    )
}

const ManagerNav = () => {
    return (
        <NavLink
            className="btn btn-ghost btn-circle"
            title="Manager"
            to="/manager"
        >
            <PieChart size="24"/>
        </NavLink>
    )
}

const EmployeeNav = () => {
    return (
        <NavLink
            className="btn btn-ghost btn-circle"
            title="Employee"
            to="/employee"
        >
            <Tool size="24"/>
        </NavLink>
    )
}

const CustomerNav = () => {
    return (
        <NavLink
            className="btn btn-ghost btn-circle"
            title="Customer"
            to="/customer"
        >
            <ShoppingCart size="24"/>
        </NavLink>
    )
}
