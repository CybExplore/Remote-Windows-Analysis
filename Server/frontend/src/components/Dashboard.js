import React from 'react';
import { Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const navigate = useNavigate();
  const { logout, passwordChanged } = useAuth();

  const handleLogout = () => {
    logout();
  };

  if (!passwordChanged) {
    console.log("Not True");
    
    return <Navigate to="/password/change" />;
  } 


  return (
    <div>
      <h2>Dashboard</h2>
      <p>Welcome to your Remote Windows Security Management System dashboard!</p>
      <button onClick={() => navigate('/profile')}>View Profile</button>
      <button onClick={() => navigate('/password/change')}>Change Password</button>
      <button onClick={handleLogout}>Logout</button>
    </div>
  );
};

export default Dashboard;
