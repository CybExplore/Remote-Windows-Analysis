import { useContext } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';

function Navbar() {
  const { logout } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <nav className="bg-blue-600 p-4">
      <div className="container mx-auto flex justify-between items-center">
        <div className="flex items-center">
          <img src="/logo.png" alt="Logo" className="h-8 mr-2" />
          <Link to="/dashboard" className="text-white text-xl font-bold">Security Monitor</Link>
        </div>
        <div className="space-x-4">
          <Link to="/dashboard" className="text-white hover:text-gray-200">Dashboard</Link>
          <Link to="/security-events" className="text-white hover:text-gray-200">Security Events</Link>
          <Link to="/user-account" className="text-white hover:text-gray-200">User Account</Link>
          <Link to="/user-groups" className="text-white hover:text-gray-200">User Groups</Link>
          <Link to="/user-profile" className="text-white hover:text-gray-200">User Profile</Link>
          <Link to="/user-sessions" className="text-white hover:text-gray-200">User Sessions</Link>
          <Link to="/environment-info" className="text-white hover:text-gray-200">Environment Info</Link>
          <Link to="/process-logs" className="text-white hover:text-gray-200">Process Logs</Link>
          <Link to="/network-logs" className="text-white hover:text-gray-200">Network Logs</Link>
          <Link to="/file-logs" className="text-white hover:text-gray-200">File Logs</Link>
          <button onClick={handleLogout} className="text-white hover:text-gray-200">Logout</button>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;
