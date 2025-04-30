import React from 'react';
import { useAuth } from '../context/AuthContext';
import { Card } from 'primereact/card';

const Home = () => {
  const { user } = useAuth();

  return (
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-3xl font-bold text-gray-700 dark:text-gray-200 mb-6">
        Welcome, {user?.full_name || user?.email}
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <Card title="System Status" className="bg-white dark:bg-gray-800 shadow-md">
          <p className="text-gray-600 dark:text-gray-300">All systems operational.</p>
        </Card>
        <Card title="Recent Activity" className="bg-white dark:bg-gray-800 shadow-md">
          <p className="text-gray-600 dark:text-gray-300">Last login: {user?.profile?.last_logon || 'N/A'}</p>
        </Card>
        <Card title="Security Alerts" className="bg-white dark:bg-gray-800 shadow-md">
          <p className="text-gray-600 dark:text-gray-300">No active alerts.</p>
        </Card>
      </div>
    </div>
  );
};

export default Home;