import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext'; // Assuming you're using an AuthContext for auth state

const ProtectedRoute = ({ component: Component }) => {
  const { isAuthenticated, passwordChanged } = useAuth();

  // Check if user is authenticated and password has been changed
  if (!isAuthenticated) {
    // Redirect unauthenticated users to login
    return <Navigate to="/login" />;
  }

  console.log(`Password has been changed: ${passwordChanged}`);
  

  // if (!passwordChanged) {
  //   // Redirect users who haven't changed their password to the password change page
  //   return <Navigate to="/password/change" />;
  // }

  // Render the component if authenticated and password has been changed
  return <Component />;
};

export default ProtectedRoute;
