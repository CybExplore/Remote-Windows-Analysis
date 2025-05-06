import React, { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { Button } from 'primereact/button';
import { toast } from 'react-toastify';
import { useAuth } from '../context/AuthContext';
import CircleSpinner from '../components/CircleSpinner';

const Logout = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = React.useState(true);

  useEffect(() => {
    const performLogout = async () => {
      try {
        console.log('Initiating logout process');
        await logout(); // Calls logout from AuthContext
        toast.success('You have been logged out.');
        // Auto-redirect to /login after 3 seconds
        setTimeout(() => {
          console.log('Redirecting to /login');
          navigate('/login');
        }, 3000);
      } catch (error) {
        console.error('Logout error:', error);
        toast.error('Failed to log out. Please try again.');
        // Redirect anyway to ensure user is logged out
        setTimeout(() => {
          console.log('Redirecting to /login after error');
          navigate('/login');
        }, 3000);
      } finally {
        setLoading(false);
      }
    };
    performLogout();
  }, [logout, navigate]);

  if (loading) {
    return (
      <div className="flex justify-center items-center h-screen bg-gray-100 dark:bg-gray-900">
        <CircleSpinner size="60px" message="Logging out..." />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="w-full max-w-md bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-8 text-center"
      >
        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
          You Have Been Logged Out
        </h2>
        <p className="text-gray-600 dark:text-gray-300 mb-6">
          You will be redirected to the login page in a few seconds.
        </p>
        <Button
          label="Go to Login"
          className="p-button-raised p-button-primary"
          onClick={() => {
            console.log('Manual redirect to /login');
            navigate('/login');
          }}
        />
      </motion.div>
    </div>
  );
};

export default Logout;