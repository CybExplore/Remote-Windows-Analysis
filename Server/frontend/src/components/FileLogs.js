// FileLogs.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function FileLogs() {
  const [fileLogs, setFileLogs] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchFileLogs = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/files/');
        setFileLogs(response.data);
      } catch (err) {
        setError('Failed to fetch file logs.');
        console.error(err);
      }
    };
    fetchFileLogs();
  }, []);

  const columns = [
    { key: 'event_type', label: 'Event Type' },
    { key: 'path', label: 'Path' },
    { key: 'change_type', label: 'Change Type' },
    { key: 'old_path', label: 'Old Path' },
    { key: 'timestamp', label: 'Timestamp' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">File Logs</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={fileLogs} />
    </div>
  );
}

export default FileLogs;
