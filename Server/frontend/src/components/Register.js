import { useState, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';

function Register() {
  const [clientId, setClientId] = useState('');
  const [secretId, setSecretId] = useState('');
  const [sid, setSid] = useState('');
  const [userEmail, setUserEmail] = useState('');
  const [fullName, setFullName] = useState('');
  const [error, setError] = useState('');
  const { register } = useContext(AuthContext);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    const success = await register(clientId, secretId, sid, userEmail, fullName);
    if (success) {
      navigate('/dashboard');
    } else {
      setError('Registration failed. Please check your details.');
    }
  };

  return (
    <div className="flex items-center justify-center min-h-screen bg-gray-100">
      <div className="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <h2 className="text-2xl font-bold mb-6 text-center">Register</h2>
        {error && <p className="text-red-500 mb-4">{error}</p>}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700">Client ID</label>
            <input
              type="text"
              value={clientId}
              onChange={(e) => setClientId(e.target.value)}
              className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Secret ID</label>
            <input
              type="password"
              value={secretId}
              onChange={(e) => setSecretId(e.target.value)}
              className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">SID</label>
            <input
              type="text"
              value={sid}
              onChange={(e) => setSid(e.target.value)}
              className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Email</label>
            <input
              type="email"
              value={userEmail}
              onChange={(e) => setUserEmail(e.target.value)}
              className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Full Name</label>
            <input
              type="text"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              className="mt-1 block w-full p-2 border border-gray-300 rounded-md"
              required
            />
          </div>
          <button
            onClick={handleSubmit}
            className="w-full bg-blue-600 text-white p-2 rounded-md hover:bg-blue-700"
          >
            Register
          </button>
          <p className="text-center text-sm">
            Already have an account? <a href="/login" className="text-blue-600 hover:underline">Login</a>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Register;