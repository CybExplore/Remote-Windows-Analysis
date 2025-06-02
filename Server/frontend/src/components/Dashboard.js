// Dashboard.js
import { Link } from 'react-router-dom';

function Dashboard() {
  return (
    <div className="container mx-auto p-6">
      <h1 className="text-3xl font-bold mb-6">Security Monitoring Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <Link to="/security-events" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">Security Events</h2>
          <p>View Windows security event logs</p>
        </Link>
        <Link to="/user-account" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">User Account</h2>
          <p>View user account details</p>
        </Link>
        <Link to="/user-groups" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">User Groups</h2>
          <p>View user group memberships</p>
        </Link>
        <Link to="/user-profile" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">User Profile</h2>
          <p>View user profile paths</p>
        </Link>
        <Link to="/user-sessions" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">User Sessions</h2>
          <p>View active user sessions</p>
        </Link>
        <Link to="/environment-info" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">Environment Info</h2>
          <p>View system environment details</p>
        </Link>
        <Link to="/process-logs" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">Process Logs</h2>
          <p>View running processes</p>
        </Link>
        <Link to="/network-logs" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">Network Logs</h2>
          <p>View network connections</p>
        </Link>
        <Link to="/file-logs" className="bg-blue-500 text-white p-4 rounded-lg hover:bg-blue-600">
          <h2 className="text-xl font-semibold">File Logs</h2>
          <p>View file system changes</p>
        </Link>
      </div>
    </div>
  );
}

export default Dashboard;