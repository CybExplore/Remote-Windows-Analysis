import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import AuthProvider from './context/AuthProvider';
import ThemeProvider from './context/ThemeProvider';
import Home from './pages/Home';
import Login from './pages/Login';
import PasswordChange from './pages/PasswordChange';
import PasswordReset from './pages/PasswordReset';
import PasswordResetConfirm from './pages/PasswordResetConfirm';
import EmailVerification from './pages/EmailVerification';
import Profile from './pages/Profile';
import Events from './pages/Events';
import ProtectedRoute from './components/ProtectedRoute';
import Logout from './pages/Logout';

function App() {
  return (
    <Router>
      <ThemeProvider>
        <AuthProvider>
          <div className="min-h-screen bg-gray-100 dark:bg-gray-900">
            <ToastContainer position="top-right" autoClose={3000} theme="colored" />
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/password/change" element={<ProtectedRoute component={PasswordChange} />} />
              <Route path="/password/reset/request" element={<PasswordReset />} />
              <Route path="/password/reset/confirm/:uidb64/:token" element={<PasswordResetConfirm />} />
              <Route path="/email-verified/success" element={<EmailVerification success />} />
              <Route path="/email-verified/failure" element={<EmailVerification success={false} />} />
              <Route path="/profile" element={<ProtectedRoute component={Profile} />} />
              <Route path="/events" element={<ProtectedRoute component={Events} />} />
              <Route path="/" element={<ProtectedRoute component={Home} />} />
              <Route
              path="/logout"
              element={
                <ProtectedRoute>
                  <Logout />
                </ProtectedRoute>
              }
            />
            </Routes>
          </div>
        </AuthProvider>
      </ThemeProvider>
    </Router>
  );
}

export default App;