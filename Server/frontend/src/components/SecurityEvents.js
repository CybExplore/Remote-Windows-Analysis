// SecurityEvents.js
import { useState, useEffect } from 'react';
import axios from 'axios';
import DataTable from './DataTable';

function SecurityEvents() {
  const [events, setEvents] = useState([]);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const response = await axios.get('http://localhost:8001/api/logs/');
        setEvents(response.data);
      } catch (err) {
        setError('Failed to fetch security events.');
        console.error(err);
      }
    };
    fetchEvents();
  }, []);

  const columns = [
    { key: 'event_id', label: 'Event ID' },
    { key: 'event_type', label: 'Event Type' },
    { key: 'source', label: 'Source' },
    { key: 'timestamp', label: 'Timestamp' },
    { key: 'details', label: 'Details' },
  ];

  return (
    <div className="container mx-auto p-6">
      <h1 className="text-2xl font-bold mb-4">Security Events</h1>
      {error && <p className="text-red-500 mb-4">{error}</p>}
      <DataTable columns={columns} data={events} />
    </div>
  );
}

export default SecurityEvents;