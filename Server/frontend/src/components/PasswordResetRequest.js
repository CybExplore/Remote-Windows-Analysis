import React from 'react';
import { useAuth } from '../context/AuthContext';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useNavigate } from 'react-router-dom';

const PasswordResetRequest = () => {
  const { requestPasswordReset } = useAuth();
  const navigate = useNavigate();

  // Validation schema for reset request
  const validationSchema = Yup.object().shape({
    identifier: Yup.string().required('SID or Email is required'),
  });

  // Formik for form management
  const formik = useFormik({
    initialValues: {
      identifier: '',
    },
    validationSchema,
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      const { success, message } = await requestPasswordReset(values.identifier);

      if (success) {
        alert(message || 'Request successful! Please check your email.');
        formik.resetForm();
      } else {
        setFieldError('identifier', message || 'Failed to request reset.');
      }

      setSubmitting(false);
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
      <div className="w-full max-w-md bg-white rounded-lg shadow-lg p-8">
        <h2 className="text-2xl font-bold text-center text-gray-700 mb-6">
          Reset Your Password
        </h2>
        <form onSubmit={formik.handleSubmit} className="space-y-6">
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
              className={`mt-1 block w-full px-4 py-2 border ${
                formik.touched.identifier && formik.errors.identifier
                  ? 'border-red-500'
                  : 'border-gray-300'
              } rounded-lg shadow-sm focus:outline-none focus:ring-2 ${
                formik.touched.identifier && formik.errors.identifier
                  ? 'focus:ring-red-500'
                  : 'focus:ring-blue-500'
              }`}
              placeholder="Enter your SID or Email"
            />
            {formik.touched.identifier && formik.errors.identifier && (
              <span className="text-red-500 text-sm">{formik.errors.identifier}</span>
            )}
          </div>
          <button
            type="submit"
            disabled={formik.isSubmitting}
            className={`w-full py-2 px-4 rounded-lg font-medium text-white ${
              formik.isSubmitting
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-indigo-600 hover:bg-indigo-500 focus:ring-2 focus:ring-indigo-500'
            }`}
          >
            {formik.isSubmitting ? 'Requesting...' : 'Request Reset Link'}
          </button>
        </form>
        <button
          onClick={() => navigate('/login')}
          className="mt-4 w-full py-2 px-4 text-indigo-600 bg-transparent font-medium hover:bg-indigo-100 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-500"
        >
          Back to Login
        </button>
      </div>
    </div>
  );
};

export default PasswordResetRequest;
