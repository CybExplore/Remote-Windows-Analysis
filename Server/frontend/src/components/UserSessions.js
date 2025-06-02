// UserSessions.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function UserSessions() {
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchSessions = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/user/profile/');
        const allSessions = response.data.flatMap(item => item.sessions);
        setSessions(allSessions);
      } catch (err) {
        setError('Failed to fetch user sessions.');
        console.error(err);
      }
    };
    fetchSessions();
  }, []);

  const columns = [
    { key: 'session_id', label: 'Session ID' },
    { key: 'start_time', label: 'Start Time' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">User Sessions</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={sessions} />
    </div>
  );
}

export default UserSessions;