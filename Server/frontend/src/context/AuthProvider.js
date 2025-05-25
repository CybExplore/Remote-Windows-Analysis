import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import AuthContext from './AuthContext';
import { CircleSpinner } from '../components/CircleSpinner';


const AuthProvider = ({ children }) => {
  // States for authentication
  const [token, setToken] = useState(localStorage.getItem('access_token') || null);
  const [sid, setSid] = useState(localStorage.getItem('sid') || null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [operationLoading, setOperationLoading] = useState(false);

  const navigate = useNavigate();

  // Fetch user data based on token and SID
  const fetchUserData = useCallback(async (token, sid) => {
    try {
      const response = await axios.get(`http://localhost:8000/api/accounts/users/${sid}/`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setUser(response.data);
    } catch (error) {
      logout(); // Logout if unable to fetch user data
    }
  }, []);

  // Initialize user data and authentication state
  useEffect(() => {
    const initializeAuth = async () => {
      const storedToken = localStorage.getItem('access_token');
      const storedSid = localStorage.getItem('sid');
      
      if (storedToken && storedSid && !user) {
        await fetchUserData(storedToken, storedSid);
      }
      setLoading(false);
    };

    initializeAuth();
  }, [fetchUserData, user]);

  // Login functionality
  const login = async (identifier, password) => {
    setOperationLoading(true);
    try {
      const response = await axios.post('http://localhost:8000/api/accounts/login/', 
        { identifier, password },
        { headers: { 'Content-Type': 'application/json' } }
      );
      
      const { access_token, user: userData } = response.data;
      setToken(access_token);
      setSid(userData.sid);
      setUser(userData);
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('sid', userData.sid);

      await fetchUserData(access_token, userData.sid);
      navigate('/');
      return { success: true, message: 'Login successful!' };
    } catch (error) {
      const errorMsg = error.response?.data?.non_field_errors || 
                      error.response?.data?.error || 
                      'Login failed.';
      return { success: false, message: `Error: ${errorMsg}` };
    } finally {
      setOperationLoading(false);
    }
  };

  // Request password reset
  const requestPasswordReset = async (identifier) => {
    setOperationLoading(true);
    try {
      const response = await axios.post(
        'http://localhost:8000/api/accounts/password/reset/request/', 
        { identifier }
      );
      return {
        success: true,
        message: response.data.message || 'Request successful! Please check your email.',
      };
    } catch (error) {
      const errorMessage = error.response?.data?.identifier || 
                         error.response?.data?.error || 
                         'Failed to request reset.';
      return { success: false, message: errorMessage };
    } finally {
      setOperationLoading(false);
    }
  };

  // Password Reset
  const passwordResetConfirm = async (uidb64, token, newPassword, confirmPassword) => {
    try {
      const response = await axios.post('http://localhost:8000/api/accounts/password/reset/confirm/', {
        uidb64,
        token,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });
      return {
        success: true,
        message: response.data.message || 'Password reset successful!',
      };
    } catch (error) {
      const errors = error.response?.data || {};
      return {
        success: false,
        message: 
          errors.new_password?.[0] ||
          errors.confirm_password?.[0] ||
          errors.token?.[0] ||
          errors.uidb64?.[0] ||
          'Failed to reset password. Please try again.',
      };
    }
  };

  // Change password
  const passwordChange = async (sid, oldPassword, newPassword) => {
    setOperationLoading(true);
    try {
      const response = await axios.post(
        'http://localhost:8000/api/accounts/password/change/',
        {
          sid,
          old_password: oldPassword,
          new_password: newPassword,
          confirm_password: newPassword, 
        },
        {
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`, 
          },
          withCredentials: true, 
        }
      );
      return {
        success: true,
        message: response.data.message || 'Password changed successfully!',
        nextSteps: response.data.next_steps || [
          'You may need to update credentials in connected systems',
          'Consider enabling two-factor authentication',
        ],
      };
    } catch (error) {
      const errorMessage = error.response?.data?.detail ||
                         Object.values(error.response?.data || {})[0]?.[0] ||
                         'Failed to change password. Please try again.';
      return {
        success: false,
        message: errorMessage,
        errorType: error.response?.status === 400 ? 'validation' : 'server',
        statusCode: error.response?.status,
      };
    } finally {
      setOperationLoading(false);
    }
  };

  // Logout functionality
  const logout = () => {
    setToken(null);
    setSid(null);
    setUser(null);
    localStorage.removeItem('access_token');
    localStorage.removeItem('sid');
    navigate('/login');
  };

  // Context value for authentication
  const value = {
    token,
    sid,
    user,
    loading: operationLoading,
    passwordChanged: user?.password_changed || false,
    login,
    logout,
    requestPasswordReset,
    passwordResetConfirm,
    passwordChange,
    isAuthenticated: !!token,
  };

  // Show loading spinner during initialization
  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen">
        <CircleSpinner size="60px" message="Loading security module..." />
      </div>
    );
  }

  return (
    <>
      {operationLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-30">
          <CircleSpinner size="50px" message="Processing..." />
        </div>
      )}
      <AuthContext.Provider value={value}>
        {children}
      </AuthContext.Provider>
    </>
  );
};

export default AuthProvider;