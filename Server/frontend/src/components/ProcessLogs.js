// ProcessLogs.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function ProcessLogs() {
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchLogs = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/processes/');
        setLogs(response.data);
      } catch (err) {
        setError('Failed to fetch process logs.');
        console.error(err);
      }
    };
    fetchLogs();
  }, []);

  const columns = [
    { key: 'name', label: 'Name' },
    { key: 'pid', label: 'PID' },
    { key: 'path', label: 'Path' },
    { key: 'start_time', label: 'Start Time' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Process Logs</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={logs} />
    </div>
  );
}

export default ProcessLogs;