import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from 'primereact/button';

const EmailVerification = ({ success }) => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 text-center">
        {success ? (
          <>
            <h2 className="text-2xl font-bold text-green-600 dark:text-green-400 mb-4">Email Verified!</h2>
            <p className="text-gray-600 dark:text-gray-300">You can now login to your account.</p>
            <Button
              label="Go to Login"
              className="mt-6 p-button-raised p-button-primary"
              onClick={() => navigate('/login')}
            />
          </>
        ) : (
          <>
            <h2 className="text-2xl font-bold text-red-600 dark:text-red-400 mb-4">Verification Failed</h2>
            <p className="text-gray-600 dark:text-gray-300">The verification link may have expired or is invalid.</p>
            <Button
              label="Back to Login"
              className="mt-6 p-button-raised p-button-secondary"
              onClick={() => navigate('/login')}
            />
          </>
        )}
      </div>
    </div>
  );
};

export default EmailVerification;