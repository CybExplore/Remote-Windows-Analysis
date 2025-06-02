// UserAccount.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function UserAccount() {
  const [account, setAccount] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchAccount = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/user/profile/');
        setAccount(response.data.map(item => item.account_info));
      } catch (err) {
        setError('Failed to fetch user account.');
        console.error(err);
      }
    };
    fetchAccount();
  }, []);

  const columns = [
    { key: 'username', label: 'Username' },
    { key: 'domain', label: 'Domain' },
    { key: 'sid', label: 'SID' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">User Account</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={account} />
    </div>
  );
}

export default UserAccount;