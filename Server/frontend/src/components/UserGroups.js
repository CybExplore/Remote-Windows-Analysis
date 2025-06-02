// UserGroups.js
import { useState, useEffect } from 'react';
import axios from 'axios';

function UserGroups() {
  const [groups, setGroups] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchGroups = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/user/profile/');
        const allGroups = response.data.flatMap(item => item.groups.groups || []);
        setGroups(allGroups);
      } catch (err) {
        setError('Failed to fetch user groups.');
        console.error(err);
      }
    };
    fetchGroups();
  }, []);

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">User Groups</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <ul className="bg-white p-4 rounded-lg shadow">
        {groups.length === 0 ? (
          <li className="py-2">No groups available</li>
        ) : (
          groups.map((group, index) => (
            <li key={index} className="py-2 border-b last:border-b-0">{group}</li>
          ))
        )}
      </ul>
    </div>
  );
}

export default UserGroups;