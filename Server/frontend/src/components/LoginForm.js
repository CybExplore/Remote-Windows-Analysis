import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate, Link } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { toast, ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

import logo from "../images/cybexplore.png";
import { CircleSpinner } from './CircleSpinner';

const LoginForm = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false); // Spinner state

  const validationSchema = Yup.object().shape({
    identifier: Yup.string().required('SID or Email is required'),
    password: Yup.string().required('Password is required'),
  });

  const formik = useFormik({
    initialValues: {
      identifier: '',
      password: '',
    },
    validationSchema,
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      setLoading(true); // Start the spinner
      try {
        const { success, message, passwordChanged } = await login(values.identifier, values.password);
        
        // Simulating a 5-second delay
        setTimeout(() => {
          setLoading(false); // Stop the spinner
          
          if (success) {
            toast.info('Please change your password for security reasons.', { position: 'top-right' });
            // navigate('/password/change');
            console.log(passwordChanged);
            
          } else if (success && passwordChanged) {
            toast.success('Login successful! Welcome back!', { position: 'top-right' });
            navigate('/');
          } else {
            toast.error(`Login failed: ${message}`, { position: 'top-right' });
            setFieldError('identifier', message.identifier);
            setFieldError('password', message.password);
          }
        }, 500);
      } catch (error) {
        toast.error('An unexpected error occurred during login. Please try again.', { position: 'top-right' });
        setLoading(false); // Stop the spinner
      } finally {
        setSubmitting(false);
      }
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
      <ToastContainer position="top-right" autoClose={500} />
      <div className="w-full max-w-md bg-white rounded-lg shadow-lg p-8">
        <div className="text-center">
          <img src={logo} alt="System Logo" className="mx-auto h-16 w-auto" />
          <h2 className="text-2xl font-bold text-gray-700 mt-4">
            Welcome Back! Please Sign In
          </h2>
        </div>
        {loading ? (
          <div className="flex justify-center items-center mt-8">
            <CircleSpinner />
          </div>
        ) : (
          <form onSubmit={formik.handleSubmit} className="mt-8 space-y-6">
            <div>
              <label
                htmlFor="identifier"
                className="block text-sm font-medium text-gray-600"
              >
                SID or Email
              </label>
              <input
                id="identifier"
                name="identifier"
                type="text"
                value={formik.values.identifier}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                className={`mt-1 w-full px-3 py-2 border ${
                  formik.touched.identifier && formik.errors.identifier
                    ? 'border-red-500'
                    : 'border-gray-300'
                } rounded-md shadow-sm focus:ring-2 focus:ring-blue-500`}
                placeholder="Enter your SID or Email"
              />
              {formik.touched.identifier && formik.errors.identifier && (
                <span className="text-red-500 text-sm">{formik.errors.identifier}</span>
              )}
            </div>
            <div>
              <label
                htmlFor="password"
                className="block text-sm font-medium text-gray-600"
              >
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                value={formik.values.password}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                className={`mt-1 w-full px-3 py-2 border ${
                  formik.touched.password && formik.errors.password
                    ? 'border-red-500'
                    : 'border-gray-300'
                } rounded-md shadow-sm focus:ring-2 focus:ring-blue-500`}
                placeholder="Enter your password"
              />
              {formik.touched.password && formik.errors.password && (
                <span className="text-red-500 text-sm">{formik.errors.password}</span>
              )}
            </div>
            <div>
              <button
                type="submit"
                disabled={formik.isSubmitting}
                className={`w-full py-2 px-4 rounded-md font-medium text-white ${
                  formik.isSubmitting
                    ? 'bg-gray-400 cursor-not-allowed'
                    : 'bg-indigo-600 hover:bg-indigo-500 focus:ring-2 focus:ring-indigo-500'
                }`}
              >
                {formik.isSubmitting ? 'Signing In...' : 'Sign In'}
              </button>
            </div>
          </form>
        )}
        <p className="mt-4 text-center text-sm text-gray-600">
          <Link
            to="/password/reset/request"
            className="text-indigo-600 hover:text-indigo-500 font-medium"
          >
            Forgot Password?
          </Link>
        </p>
      </div>
    </div>
  );
};

export default LoginForm;