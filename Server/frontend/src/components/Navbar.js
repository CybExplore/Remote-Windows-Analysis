import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { Menubar } from 'primereact/menubar';
import { Button } from 'primereact/button';

const Navbar = () => {
  const { user, logout, isAuthenticated } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const items = isAuthenticated
    ? [
        { label: 'Dashboard', icon: 'pi pi-home', command: () => navigate('/') },
        { label: 'Profile', icon: 'pi pi-user', command: () => navigate('/profile') },
        {
          label: 'Account',
          icon: 'pi pi-cog',
          items: [
            { label: 'Change Password', icon: 'pi pi-key', command: () => navigate('/password/change') },
            { label: 'Logout', icon: 'pi pi-sign-out', command: logout },
          ],
        },
      ]
    : [
        { label: 'Login', icon: 'pi pi-sign-in', command: () => navigate('/login') },
      ];

  const end = (
    <div className="flex items-center gap-4">
      <Button
        icon={theme === 'light' ? 'pi pi-moon' : 'pi pi-sun'}
        className="p-button-rounded p-button-text"
        onClick={toggleTheme}
      />
      {isAuthenticated && (
        <span className="text-gray-700 dark:text-gray-200">
          {user?.full_name || user?.email}
        </span>
      )}
    </div>
  );

  return (
    <nav className="bg-white dark:bg-gray-800 shadow-md">
      <Menubar
        model={items}
        end={end}
        className="max-w-7xl mx-auto px-4 py-2"
      />
    </nav>
  );
};

export default Navbar;