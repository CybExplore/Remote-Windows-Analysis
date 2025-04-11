import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Navigate, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const Profile = () => {
  const [userData, setUserData] = useState(null);
  const [message, setMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const { token, sid, passwordChanged } = useAuth();

  
  useEffect(() => {
    const fetchProfile = async () => {
      if (!token || !sid) {
        setMessage('Error: You must be logged in to view your profile.');
        navigate('/login');
        return;
      }

      try {
        const response = await axios.get(`http://localhost:8000/api/users/${sid}/`, {
          headers: { 'Authorization': `Bearer ${token}` },
        });
        setUserData(response.data);
        console.log('Profile data:', response.data);
      } catch (error) {
        setMessage('Error: ' + (error.response?.data?.detail || error.message));
        console.error('Error fetching profile:', error.response?.data || error);
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [token, sid, navigate]);

  if (loading) return <p>Loading profile...</p>;
  if (message) return <p>{message}</p>;

  if (!passwordChanged) {
    console.log("Not True");
    
    return <Navigate to="/password/change" />;
  } 


  return (
    <div>
      <h2>Your Profile</h2>
      {userData && (
        <div>
          <p><strong>SID:</strong> {userData.sid}</p>
          <p><strong>Email:</strong> {userData.email}</p>
          <p><strong>Full Name:</strong> {userData.full_name || 'Not set'}</p>
          <p><strong>Domain:</strong> {userData.domain || 'Not set'}</p>
          <p><strong>Account Type:</strong> {userData.account_type || 'Not set'}</p>
          <p><strong>Status:</strong> {userData.status || 'Not set'}</p>
          <p><strong>Last Updated:</strong> {new Date(userData.updated_at).toLocaleString()}</p>
          {userData.profile && (
            <>
              <p><strong>Last Password Change:</strong> {userData.profile.last_password_change ? new Date(userData.profile.last_password_change).toLocaleString() : 'Not set'}</p>
              <p><strong>Department:</strong> {userData.profile.department || 'Not set'}</p>
              <p><strong>Job Title:</strong> {userData.profile.job_title || 'Not set'}</p>
            </>
          )}
        </div>
      )}
      <button onClick={() => navigate('/')}>Back to Dashboard</button>
    </div>
  );
};

export default Profile;
