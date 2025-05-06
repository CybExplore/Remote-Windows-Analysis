import React from 'react';
import { Menubar } from 'primereact/menubar';
import { Button } from 'primereact/button';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { useNavigate } from 'react-router-dom';

const Navbar = () => {
  const { user } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const items = [
    {
      label: 'Home',
      icon: 'pi pi-home',
      command: () => navigate('/'),
    },
    {
      label: 'Profile',
      icon: 'pi pi-user',
      command: () => navigate('/profile'),
    },
    {
      label: 'Events',
      icon: 'pi pi-calendar',
      command: () => navigate('/events'),
    },
    {
      label: 'Logout',
      icon: 'pi pi-sign-out',
      command: () => navigate('/logout'), // Link to /logout route
    },
  ];

  const start = (
    <div className="flex items-center">
      <span className="text-lg font-semibold text-gray-900 dark:text-white mr-4">
        {user?.full_name || 'User'}
      </span>
    </div>
  );

  const end = (
    <Button
      icon={theme === 'light' ? 'pi pi-moon' : 'pi pi-sun'}
      className="p-button-text p-button-rounded"
      onClick={toggleTheme}
      label="Toggle Theme"
      aria-label="Toggle Theme"
    />
  );

  return (
    <div className="bg-white dark:bg-gray-800 shadow-md">
      <Menubar model={items} start={start} end={end} className="container mx-auto px-4" />
    </div>
  );
};

export default Navbar;