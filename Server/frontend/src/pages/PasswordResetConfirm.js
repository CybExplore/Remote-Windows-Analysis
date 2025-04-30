import React from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../context/AuthContext';
import { Password } from 'primereact/password';
import { Button } from 'primereact/button';
import { REGEX } from '../utils/constants';

const PasswordResetConfirm = () => {
  const { passwordResetConfirm } = useAuth();
  const { uidb64, token } = useParams();
  const navigate = useNavigate();

  const formik = useFormik({
    initialValues: {
      newPassword: '',
      confirmPassword: '',
    },
    validationSchema: Yup.object({
      newPassword: Yup.string()
        .required('New Password is required')
        .matches(REGEX.PASSWORD, 'Password must include uppercase, lowercase, number, and special character'),
      confirmPassword: Yup.string()
        .oneOf([Yup.ref('newPassword'), null], 'Passwords must match')
        .required('Confirm Password is required'),
    }),
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      const { success, message } = await passwordResetConfirm(uidb64, token, values.newPassword, values.confirmPassword);
      if (!success) {
        setFieldError('newPassword', message);
      }
      setSubmitting(false);
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
        <h2 className="text-2xl font-bold text-center text-gray-700 dark:text-gray-200 mb-6">
          Confirm Password Reset
        </h2>
        <form onSubmit={formik.handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="newPassword" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              New Password
            </label>
            <Password
              id="newPassword"
              name="newPassword"
              value={formik.values.newPassword}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.newPassword && formik.errors.newPassword ? 'p-invalid' : ''}`}
              placeholder="Enter new password"
              toggleMask
            />
            {formik.touched.newPassword && formik.errors.newPassword && (
              <span className="text-red-500 text-sm">{formik.errors.newPassword}</span>
            )}
          </div>
          <div>
            <label htmlFor="confirmPassword" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Confirm Password
            </label>
            <Password
              id="confirmPassword"
              name="confirmPassword"
              value={formik.values.confirmPassword}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.confirmPassword && formik.errors.confirmPassword ? 'p-invalid' : ''}`}
              placeholder="Confirm new password"
              toggleMask
            />
            {formik.touched.confirmPassword && formik.errors.confirmPassword && (
              <span className="text-red-500 text-sm">{formik.errors.confirmPassword}</span>
            )}
          </div>
          <Button
            type="submit"
            label={formik.isSubmitting ? 'Resetting...' : 'Reset Password'}
            disabled={formik.isSubmitting}
            className="w-full p-button-raised p-button-primary"
          />
        </form>
        <Button
          label="Back to Login"
          className="w-full mt-4 p-button-text p-button-secondary"
          onClick={() => navigate('/login')}
        />
      </div>
    </div>
  );
};

export default PasswordResetConfirm;