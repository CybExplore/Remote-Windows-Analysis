// EnvironmentInfo.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function EnvironmentInfo() {
  const [info, setInfo] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchInfo = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/user/profile/');
        setInfo(response.data.map(item => item.environment));
      } catch (err) {
        setError('Failed to fetch environment info.');
        console.error(err);
      }
    };
    fetchInfo();
  }, []);

  const columns = [
    { key: 'os_version', label: 'OS Version' },
    { key: 'machine_name', label: 'Machine Name' },
    { key: 'processor_count', label: 'Processor Count' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Environment Info</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={info} />
    </div>
  );
}

export default EnvironmentInfo;