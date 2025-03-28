import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Menu, Button, Avatar, Dropdown } from 'antd';
import { UserOutlined, LoginOutlined, LogoutOutlined } from '@ant-design/icons';
import { toast } from 'react-toastify';
import { useAuth } from '../context/AuthContext';

const Navbar = () => {
  const { user, isAuthenticated, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    toast.success('Logged out successfully!', {
      position: 'top-right',  
      // position: 'bottom-right',
      autoClose: 5000,
      style: { backgroundColor: '#4CAF50', color: '#fff' },
    
    });
    navigate('/login');
  };

  const userMenuItems = [
    {
      key: 'profile',
      label: <Link to="/profile">Profile</Link>,
    },
    {
      key: 'logout',
      label: (
        <span onClick={handleLogout}>
          <LogoutOutlined /> Logout
        </span>
      ),
    },
  ];

  const menuItems = [
    {
      key: 'dashboard',
      label: <Link to="/">Dashboard</Link>,
    },
    {
      key: 'auth',
      label: isAuthenticated ? (
        <Dropdown menu={{ items: userMenuItems }} placement="bottomRight">
          <div style={{ display: 'flex', alignItems: 'center', cursor: 'pointer' }}>
            <Avatar icon={<UserOutlined />} style={{ marginRight: 8 }} />
            <span>{user?.email || user?.sid || 'User'}</span>
          </div>
        </Dropdown>
      ) : (
        <Button
          type="primary"
          icon={<LoginOutlined />}
          onClick={() => {
            toast.info('Redirecting to login...', {
              position: 'top-right',
            });
            navigate('/login');
          }}
        >
          Login
        </Button>
      ),
      style: { marginLeft: 'auto' },
    },
  ];

  return (
    <Menu mode="horizontal" theme="dark" style={{ lineHeight: '64px' }} items={menuItems} />
  );
};

export default Navbar;