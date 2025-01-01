import Footer from '../component/layout/footer';
import Navigation from '../component/layout/navigation';

const NotFoundPage = () => {
    return (
        <>
            <Navigation/>
            <main className="flex flex-grow justify-center items-center w-full gap-5 bg-base text-base-content">
                <span className="font-mono text-base xl:text-xl">404 Page not found</span>
            </main>
            <Footer/>
        </>
    )
}

export default NotFoundPage;
