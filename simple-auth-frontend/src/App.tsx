import React from 'react';
import Layout from './components/layout/Layout';
import { BrowserRouter, Route, Routes } from 'react-router-dom';
import HomePage from './pages/HomePage';
import LogInPage from './pages/LogInPage';
import SignUpPage from './pages/SignUpPage';

function App() {
    return (
        <BrowserRouter>
            <Layout>
                <Routes>
                    <Route path="/" element={<HomePage/>}/>
                    <Route path="/log-in" element={<LogInPage/>}/>
                    <Route path="/sign-up" element={<SignUpPage/>}/>
                    <Route path="*" element={<HomePage/>}/>
                </Routes>
            </Layout>
        </BrowserRouter>
    );
}

export default App;
