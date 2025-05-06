import React from 'react';
  import { ProgressSpinner } from 'primereact/progressspinner';

  const CircleSpinner = ({ size = '50px', message = 'Loading...' }) => {
    return (
      <div className="flex flex-col items-center justify-center">
        <ProgressSpinner style={{ width: size, height: size }} strokeWidth="4" />
        <p className="mt-2 text-gray-600 dark:text-gray-300">{message}</p>
      </div>
    );
  };

  export default CircleSpinner;