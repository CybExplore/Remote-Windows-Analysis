import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useFormik } from 'formik';
import * as Yup from 'yup';

const PasswordResetConfirm = () => {
  const { passwordResetConfirm } = useAuth(); // Use the method from AuthContext
  const { uidb64, token } = useParams(); // Extract from URL
  const navigate = useNavigate();

  // Validation schema for the form
  const validationSchema = Yup.object().shape({
    newPassword: Yup.string().required('New Password is required').min(8, 'Password must be at least 8 characters'),
    confirmPassword: Yup.string().oneOf([Yup.ref('newPassword'), null], 'Passwords must match').required('Confirm Password is required'),
  });

  // Formik for managing form state and submission
  const formik = useFormik({
    initialValues: {
      newPassword: '',
      confirmPassword: '',
    },
    validationSchema,
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      const { success, message } = await passwordResetConfirm(uidb64, token, values.newPassword, values.confirmPassword);

      if (success) {
        alert(message || 'Password reset successful!');
        navigate('/login'); // Redirect to login after success
      } else {
        setFieldError('newPassword', message || 'Failed to reset password.');
        setFieldError('confirmPassword', message || 'Failed to reset password.');
      }

      setSubmitting(false);
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 px-4">
      <div className="w-full max-w-md bg-white rounded-lg shadow-lg p-8">
        <h2 className="text-2xl font-bold text-center text-gray-700 mb-6">
          Confirm Password Reset
        </h2>
        <form onSubmit={formik.handleSubmit} className="space-y-6">
          <div>
            <label
              htmlFor="newPassword"
              className="block text-sm font-medium text-gray-600"
            >
              New Password
            </label>
            <input
              id="newPassword"
              name="newPassword"
              type="password"
              value={formik.values.newPassword}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`mt-1 block w-full px-4 py-2 border ${
                formik.touched.newPassword && formik.errors.newPassword
                  ? 'border-red-500'
                  : 'border-gray-300'
              } rounded-lg shadow-sm focus:outline-none focus:ring-2 ${
                formik.touched.newPassword && formik.errors.newPassword
                  ? 'focus:ring-red-500'
                  : 'focus:ring-blue-500'
              }`}
              placeholder="Enter your new password"
            />
            {formik.touched.newPassword && formik.errors.newPassword && (
              <span className="text-red-500 text-sm">{formik.errors.newPassword}</span>
            )}
          </div>
          <div>
            <label
              htmlFor="confirmPassword"
              className="block text-sm font-medium text-gray-600"
            >
              Confirm Password
            </label>
            <input
              id="confirmPassword"
              name="confirmPassword"
              type="password"
              value={formik.values.confirmPassword}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`mt-1 block w-full px-4 py-2 border ${
                formik.touched.confirmPassword && formik.errors.confirmPassword
                  ? 'border-red-500'
                  : 'border-gray-300'
              } rounded-lg shadow-sm focus:outline-none focus:ring-2 ${
                formik.touched.confirmPassword && formik.errors.confirmPassword
                  ? 'focus:ring-red-500'
                  : 'focus:ring-blue-500'
              }`}
              placeholder="Confirm your password"
            />
            {formik.touched.confirmPassword && formik.errors.confirmPassword && (
              <span className="text-red-500 text-sm">{formik.errors.confirmPassword}</span>
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
            {formik.isSubmitting ? 'Resetting...' : 'Reset Password'}
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

export default PasswordResetConfirm;
