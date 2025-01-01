import { ExternalLink } from 'react-feather';
import { NavLink } from 'react-router-dom';

const Footer = () => {
    return (
        <>
            <footer className="footer p-2 bg-base-300 text-base-content">
                <aside className="flex flex-col justify-center items-center">
                    <NavLink
                        title="Simple Auth React"
                        to="/"
                    >
                        <img
                            className="object-scale-down object-center w-24 h-24 xl:w-32 xl:h-32"
                            src="/logo.webp"
                            alt="Logo"
                        />
                    </NavLink>
                    <span className="w-full text-center text-xs xl:text-sm">Simple Auth React</span>
                </aside>
            </footer>
            <div className="py-2 text-xs xl:text-sm bg-base-100 text-base-content">
                <div className="container px-5 m-auto">
                    <div className="flex gap-1 justify-center">
                        <span>© 2024 Copyright:</span>
                        <a
                            className="link"
                            href="https://www.janobono.com"
                        >
                            <div className="flex items-center"><span>janobono</span><ExternalLink size="18"/></div>
                        </a>
                    </div>
                </div>
            </div>
        </>
    )
}

export default Footer;
