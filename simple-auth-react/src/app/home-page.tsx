import Footer from '../component/layout/footer';
import Navigation from '../component/layout/navigation';

const HomePage = () => {
    return (
        <>
            <Navigation/>
            <main className="flex-grow">
                <div
                    className="flex flex-col justify-start items-center w-full p-2 gap-2 bg-base">
                    <h1>Home Page</h1>
                </div>
            </main>
            <Footer/>
        </>
    )
}

export default HomePage;
