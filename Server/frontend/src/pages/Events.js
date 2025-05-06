import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../utils/api';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { InputText } from 'primereact/inputtext';
import { Button } from 'primereact/button';
import { toast } from 'react-toastify';

const Events = () => {
  const navigate = useNavigate();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filters, setFilters] = useState({
    event_id: '',
    source: '',
    page: 1,
    page_size: 10,
  });
  const [totalRecords, setTotalRecords] = useState(0);

  useEffect(() => {
    const fetchEvents = async () => {
      try {
        const params = {
          event_id: filters.event_id || undefined,
          source: filters.source || undefined,
          page: filters.page,
          page_size: filters.page_size,
          ordering: '-time_created',
        };
        const response = await api.get('/events/', { params });
        setEvents(response.data.results);
        setTotalRecords(response.data.count);
      } catch (error) {
        toast.error('Failed to load security events.');
      } finally {
        setLoading(false);
      }
    };
    fetchEvents();
  }, [filters]);

  const handleFilterChange = (e) => {
    const { name, value } = e.target;
    setFilters((prev) => ({ ...prev, [name]: value, page: 1 }));
  };

  const handlePageChange = (event) => {
    setFilters((prev) => ({
      ...prev,
      page: event.page + 1,
      page_size: event.rows,
    }));
  };

  const columns = [
    { field: 'event_id', header: 'Event ID' },
    { field: 'time_created', header: 'Time', body: (row) => new Date(row.time_created).toLocaleString() },
    { field: 'source', header: 'Source' },
    { field: 'description', header: 'Description' },
    { field: 'logon_type', header: 'Logon Type' },
    { field: 'target_account', header: 'Target Account' },
  ];

  return (
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-3xl font-bold text-gray-700 dark:text-gray-200 mb-6">Security Events</h2>
      <div className="flex flex-col md:flex-row gap-4 mb-6">
        <InputText
          name="event_id"
          value={filters.event_id}
          onChange={handleFilterChange}
          placeholder="Filter by Event ID"
          className="p-inputtext-sm"
        />
        <InputText
          name="source"
          value={filters.source}
          onChange={handleFilterChange}
          placeholder="Filter by Source"
          className="p-inputtext-sm"
        />
      </div>
      <DataTable
        value={events}
        loading={loading}
        paginator
        rows={filters.page_size}
        totalRecords={totalRecords}
        onPage={handlePageChange}
        responsiveLayout="scroll"
        className="p-datatable-sm"
      >
        {columns.map((col) => (
          <Column key={col.field} field={col.field} header={col.header} body={col.body} />
        ))}
      </DataTable>
      <Button
        label="Back to Dashboard"
        className="mt-4 p-button-text p-button-secondary"
        onClick={() => navigate('/')}
      />
    </div>
  );
};

export default Events;