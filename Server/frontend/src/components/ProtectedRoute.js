import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ component: Component }) => {
  const { isAuthenticated, passwordChanged } = useAuth();

  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }

  if (!passwordChanged) {
    return <Navigate to="/password/change" />;
  }

  return <Component />;
};

export default ProtectedRoute;
