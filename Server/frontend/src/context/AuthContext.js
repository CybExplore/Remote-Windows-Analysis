import { createContext, useState, useEffect, useContext } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(localStorage.getItem('accessToken'));
  const [refreshToken, setRefreshToken] = useState(localStorage.getItem('refreshToken'));
  const [isFirstLogin, setIsFirstLogin] = useState(false);
  const API_URL = 'http://localhost:8001/api/';
  
  // const navigate = useNavigate();

  useEffect(() => {
    if (accessToken) {
      setUser({ identifier: localStorage.getItem('identifier') });
      setIsFirstLogin(localStorage.getItem('isFirstLogin') === 'true');
      refreshAccessToken();
    }
  }, []);

  useEffect(() => {
    if (user && isFirstLogin) {
      // navigate('/change-password');
      window.location.pathname = '/change-password';
      
    }
  }, [user, isFirstLogin]);
  // }, [user, isFirstLogin, navigate]);

  const login = async (identifier, password) => {
    try {
      const response = await axios.post(`${API_URL}auth/login/`, { identifier, password });
      const { access_token, refresh_token, user: userData } = response.data;
      setAccessToken(access_token);
      setRefreshToken(refresh_token);
      setUser({ identifier: userData.email || userData.sid });
      setIsFirstLogin(userData.is_first_login);
      localStorage.setItem('accessToken', access_token);
      localStorage.setItem('refreshToken', refresh_token);
      localStorage.setItem('identifier', userData.email || userData.sid);
      localStorage.setItem('isFirstLogin', userData.is_first_login.toString());
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      return true;
    } catch (error) {
      console.error('Login failed:', error.response?.data || error.message);
      return false;
    }
  };

  const register = async (email, password, sid, fullName) => {
    try {
      const response = await axios.post(`${API_URL}auth/register/`, {
        email,
        password,
        sid,
        full_name: fullName,
      });
      const { access_token, refresh_token, user: userData } = response.data;
      setAccessToken(access_token);
      setRefreshToken(refresh_token);
      setUser({ identifier: userData.email || userData.sid });
      setIsFirstLogin(userData.is_first_login);
      localStorage.setItem('accessToken', access_token);
      localStorage.setItem('refreshToken', refresh_token);
      localStorage.setItem('identifier', userData.email || userData.sid);
      localStorage.setItem('isFirstLogin', userData.is_first_login.toString());
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
      return true;
    } catch (error) {
      console.error('Registration failed:', error.response?.data || error.message);
      return false;
    }
  };

  const changePassword = async (currentPassword, newPassword) => {
    try {
      const response = await axios.post(
        `${API_URL}auth/change-password/`,
        { current_password: currentPassword, new_password: newPassword },
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );

      console.log(response);

      setIsFirstLogin(false);
      localStorage.setItem('isFirstLogin', 'false');
      return true;

    } catch (error) {
      console.error('Password change failed:', error.response?.data || error.message);
      return false;
    }
  };

  const refreshAccessToken = async () => {
    try {
      const response = await axios.post(`${API_URL}auth/refresh/`, {
        refresh_token: refreshToken,
      });
      const { access_token, refresh_token } = response.data;
      setAccessToken(access_token);
      setRefreshToken(refresh_token);
      localStorage.setItem('accessToken', access_token);
      localStorage.setItem('refreshToken', refresh_token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
    } catch (error) {
      console.error('Token refresh failed:', error.response?.data || error.message);
      logout();
    }
  };

  const logout = () => {
    setUser(null);
    setAccessToken(null);
    setRefreshToken(null);
    setIsFirstLogin(false);
    localStorage.removeItem('accessToken');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('identifier');
    localStorage.removeItem('isFirstLogin');
    delete axios.defaults.headers.common['Authorization'];
  };

  useEffect(() => {
    const interval = setInterval(refreshAccessToken, 15 * 60 * 1000);
    return () => clearInterval(interval);
  }, [refreshToken]);

  return (
    <AuthContext.Provider value={{ user, login, register, changePassword, logout, accessToken, isFirstLogin }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

