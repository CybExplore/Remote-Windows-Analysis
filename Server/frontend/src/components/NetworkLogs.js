// NetworkLogs.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function NetworkLogs() {
  const [networkLogs, setNetworkLogs] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchNetworkLogs = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/network/');
        setNetworkLogs(response.data);
      } catch (err) {
        setError('Failed to fetch network logs.');
        console.error(err);
      }
    };
    fetchNetworkLogs();
  }, []);

  const columns = [
    { key: 'local_address', label: 'Local Address' },
    { key: 'remote_address', label: 'Remote Address' },
    { key: 'state', label: 'State' },
    { key: 'timestamp', label: 'Timestamp' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Network Logs</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={networkLogs} />
    </div>
  );
}

export default NetworkLogs;
