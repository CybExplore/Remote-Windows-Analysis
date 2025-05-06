import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import AuthContext from './AuthContext';
import api from '../utils/api';
import CircleSpinner from '../components/CircleSpinner';

const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(localStorage.getItem('access_token') || null);
  const [sid, setSid] = useState(localStorage.getItem('sid') || null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [operationLoading, setOperationLoading] = useState(false);
  const navigate = useNavigate();

  const fetchUserData = useCallback(async (token, sid) => {
    try {
      const response = await api.get(`/users/${sid}/`);
      setUser(response.data.data);
      console.log(token);
    } catch (error) {
      toast.error('Failed to fetch user data. Logging out.');
      logout();
    }
  }, []);

  useEffect(() => {
    const initializeAuth = async () => {
      if (token && sid && !user) {
        await fetchUserData(token, sid);
      }
      setLoading(false);
    };
    initializeAuth();
  }, [token, sid, user, fetchUserData]);

  const login = async (identifier, password) => {
    setOperationLoading(true);
    try {
      const url = `${process.env.REACT_APP_API_URL}/login/`;
      console.log('Environment API_URL:', process.env.REACT_APP_API_URL);
      console.log('Submitting login to:', url);
      console.log('Axios baseURL:', api.defaults.baseURL);
      console.log('Login payload:', { identifier, password });

      const response = await api.post('/login/', { identifier, password });
      const { access_token, user: userData } = response.data.data;
      setToken(access_token);
      setSid(userData.sid);
      setUser(userData);
      localStorage.setItem('access_token', access_token);
      localStorage.setItem('sid', userData.sid);
      toast.success('Login successful!');
      navigate('/');
      return { success: true, message: 'Login successful!' };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.non_field_errors?.[0] || 'Login failed.';
      console.error('Login error:', errorMsg, error.response?.data);
      console.error('Error details:', error);

      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    } finally {
      setOperationLoading(false);
    }
  };

  // const register = async (data) => {
  //   setOperationLoading(true);
  //   try {
  //     const response = await api.post('/create-user/', data);
  //     toast.success('Registration successful! Check your email for password reset instructions.');
  //     navigate('/login');
  //     return { success: true, message: response.data.message };
  //   } catch (error) {
  //     const errorMsg = error.response?.data?.errors?.[0] || 'Registration failed.';
  //     toast.error(errorMsg);
  //     return { success: false, message: errorMsg };
  //   } finally {
  //     setOperationLoading(false);
  //   }
  // };

  const requestPasswordReset = async (identifier) => {
    setOperationLoading(true);
    try {
      const response = await api.post('/password/reset/request/', { identifier });
      toast.success(response.data.message);
      return { success: true, message: response.data.message };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.identifier?.[0] || 'Failed to request reset.';
      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    } finally {
      setOperationLoading(false);
    }
  };

  const passwordResetConfirm = async (uidb64, token, newPassword, confirmPassword) => {
    setOperationLoading(true);
    try {
      const response = await api.post('/password/reset/confirm/', {
        uidb64,
        token,
        new_password: newPassword,
        confirm_password: confirmPassword,
      });
      toast.success(response.data.message);
      navigate('/login');
      return { success: true, message: response.data.message };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.[0] || 'Failed to reset password.';
      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    } finally {
      setOperationLoading(false);
    }
  };

  const passwordChange = async (oldPassword, newPassword) => {
    setOperationLoading(true);
    try {
      const response = await api.post('/password/change/', {
        old_password: oldPassword,
        new_password: newPassword,
        confirm_password: newPassword,
      });
      toast.success(response.data.message);
      return { success: true, message: response.data.message };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.[0] || 'Failed to change password.';
      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    } finally {
      setOperationLoading(false);
    }
  };

  const sendEmailVerification = async (email) => {
    try {
      const response = await api.post('/email/verify/', { email });
      toast.success(response.data.message);
      return { success: true, message: response.data.message };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.[0] || 'Failed to send verification email.';
      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    }
  };

  const verifyEmail = async (uidb64, token) => {
    try {
      const response = await api.post('/email/verify/confirm/', { uidb64, token });
      toast.success(response.data.message);
      return { success: true, message: response.data.message };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.[0] || 'Verification failed.';
      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    }
  };

  const updateProfile = async (sid, profileData) => {
    try {
      const response = await api.post(`/profile/${sid}/`, { sid, profile: profileData });
      setUser((prev) => ({ ...prev, profile: response.data.data }));
      toast.success('Profile updated successfully!');
      return { success: true, message: 'Profile updated successfully!' };
    } catch (error) {
      const errorMsg = error.response?.data?.errors?.[0] || 'Failed to update profile.';
      toast.error(errorMsg);
      return { success: false, message: errorMsg };
    }
  };

  const logout = () => {
    setOperationLoading(true);
    api.post('/logout/')
      .then(() => {
        setToken(null);
        setSid(null);
        setUser(null);
        localStorage.removeItem('access_token');
        localStorage.removeItem('sid');
        toast.success('Logged out successfully!');
        navigate('/login');
      })
      .catch(() => toast.error('Failed to logout.'))
      .finally(() => setOperationLoading(false));
  };

  const value = {
    token,
    sid,
    user,
    loading: operationLoading,
    passwordChanged: user?.password_changed || false,
    isAuthenticated: !!token && !!user,
    login,
    // register,
    logout,
    requestPasswordReset,
    passwordResetConfirm,
    passwordChange,
    sendEmailVerification,
    verifyEmail,
    updateProfile,
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen bg-gray-100 dark:bg-gray-900">
        <CircleSpinner size="60px" message="Initializing security module..." />
      </div>
    );
  }

  return (
    <>
      {operationLoading && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
          <CircleSpinner size="50px" message="Processing..." />
        </div>
      )}
      <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
    </>
  );
};

export default AuthProvider;