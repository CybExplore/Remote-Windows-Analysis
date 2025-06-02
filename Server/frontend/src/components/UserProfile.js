// UserProfile.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function UserProfile() {
  const [profiles, setProfiles] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchProfiles = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/user/profile/');
        setProfiles(response.data.map(item => item.profiles));
      } catch (err) {
        setError('Failed to fetch user profiles.');
        console.error(err);
      }
    };
    fetchProfiles();
  }, []);

  const columns = [
    { key: 'profile_path', label: 'Profile Path' },
    { key: 'roaming_profile', label: 'Roaming Profile' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">User Profile</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={profiles} />
    </div>
  );
}

export default UserProfile;
