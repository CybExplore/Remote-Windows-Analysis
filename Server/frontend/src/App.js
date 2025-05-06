import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import AuthProvider from './context/AuthProvider';
import LoginForm from './components/LoginForm';
import PasswordChangeForm from './components/PasswordChangeForm';
import Dashboard from './components/Dashboard';
import Profile from './components/Profile';
import ProtectedRoute from './components/ProtectedRoute';
import Navbar from './components/Navbar';
import PasswordResetRequest from './components/PasswordResetRequest';
import PasswordResetConfirm from './components/PasswordResetConfirm';
import { ToastContainer } from 'react-toastify';


import 'react-toastify/dist/ReactToastify.css';
import "primereact/resources/themes/saga-blue/theme.css"; // Theme
import "primereact/resources/primereact.min.css";         // Core
import "primeicons/primeicons.css";                      // Icons

function App() {
  return (
    <Router>
      <AuthProvider>
      <div className="App">
        <Navbar />
        <ToastContainer position="top-right" autoClose={500} />
        <Routes>
          <Route path="/login" element={<LoginForm />} />
          <Route path="/password/change" element={<ProtectedRoute component={PasswordChangeForm} />} />
          <Route path="/password/reset/request" element={<PasswordResetRequest />} />
          <Route path="/password/reset/confirm/:uidb64/:token" element={<PasswordResetConfirm />} />

          <Route path="/" element={<ProtectedRoute component={Dashboard} />} />
          <Route path="/profile" element={<ProtectedRoute component={Profile} />} />
        </Routes>
      </div>
      </AuthProvider>
    </Router>
  );
}

export default App;
