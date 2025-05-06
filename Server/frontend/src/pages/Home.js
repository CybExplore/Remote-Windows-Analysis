import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../utils/api';
import { Card } from 'primereact/card';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Button } from 'primereact/button';
import { toast } from 'react-toastify';
import Navbar from '../components/Navbar';

const Home = () => {
  const { user } = useAuth();
  const [dashboardData, setDashboardData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        const response = await api.get('/dashboard/');
        setDashboardData(response.data.data);
      } catch (error) {
        toast.error('Failed to load dashboard data.');
      } finally {
        setLoading(false);
      }
    };
    fetchDashboardData();
  }, []);

  const eventColumns = [
    { field: 'event_id', header: 'Event ID' },
    { field: 'time_created', header: 'Time', body: (row) => new Date(row.time_created).toLocaleString() },
    { field: 'source', header: 'Source' },
    { field: 'description', header: 'Description' },
  ];

  const serverColumns = [
    { field: 'machine_name', header: 'Machine Name' },
    { field: 'os_version', header: 'OS Version' },
    { field: 'processor_count', header: 'Processors' },
    { field: 'timestamp', header: 'Timestamp', body: (row) => new Date(row.timestamp).toLocaleString() },
  ];

  if (loading) {
    return <div className="flex justify-center items-center h-screen">Loading...</div>;
  }

  return (
    <>
    <Navbar />
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-3xl font-bold text-gray-700 dark:text-gray-200 mb-6">
        Welcome, {user?.full_name || user?.email}
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <Card title="System Status" className="bg-white dark:bg-gray-800 shadow-md">
          <p className="text-gray-600 dark:text-gray-300">
            {dashboardData?.stats?.firewall_enabled ? 'Firewall Enabled' : 'Firewall Disabled'}
          </p>
          <p className="text-gray-600 dark:text-gray-300">Servers: {dashboardData?.stats?.total_servers}</p>
        </Card>
        <Card title="Security Alerts" className="bg-white dark:bg-gray-800 shadow-md">
          <p className="text-gray-600 dark:text-gray-300">Total Events: {dashboardData?.stats?.total_events}</p>
          <Button
            label="View All Events"
            className="mt-4 p-button-text p-button-primary"
            onClick={() => window.location.href = '/events'}
          />
        </Card>
        <Card title="Recent Activity" className="bg-white dark:bg-gray-800 shadow-md">
          <p className="text-gray-600 dark:text-gray-300">
            Last Login: {user?.profile?.last_logon ? new Date(user.profile.last_logon).toLocaleString() : 'N/A'}
          </p>
        </Card>
      </div>
      <div className="mb-8">
        <h3 className="text-xl font-semibold text-gray-700 dark:text-gray-200 mb-4">Recent Security Events</h3>
        <DataTable
          value={dashboardData?.recent_events || []}
          responsiveLayout="scroll"
          className="p-datatable-sm"
        >
          {eventColumns.map((col) => (
            <Column key={col.field} field={col.field} header={col.header} body={col.body} />
          ))}
        </DataTable>
      </div>
      <div>
        <h3 className="text-xl font-semibold text-gray-700 dark:text-gray-200 mb-4">Server Information</h3>
        <DataTable
          value={dashboardData?.server_infos || []}
          responsiveLayout="scroll"
          className="p-datatable-sm"
        >
          {serverColumns.map((col) => (
            <Column key={col.field} field={col.field} header={col.header} body={col.body} />
          ))}
        </DataTable>
      </div>
    </div>
    </>
  );
};

export default Home;