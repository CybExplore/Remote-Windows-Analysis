import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../context/AuthContext';
import { InputText } from 'primereact/inputtext';
import { Button } from 'primereact/button';
import { REGEX } from '../utils/constants';

const PasswordReset = () => {
  const { requestPasswordReset } = useAuth();
  const navigate = useNavigate();

  const formik = useFormik({
    initialValues: {
      identifier: '',
    },
    validationSchema: Yup.object({
      identifier: Yup.string()
        .required('SID or Email is required')
        .test('is-valid-identifier', 'Invalid SID or Email', (value) =>
          REGEX.EMAIL.test(value) || REGEX.SID.test(value)
        ),
    }),
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      const { success, message } = await requestPasswordReset(values.identifier);
      if (!success) {
        setFieldError('identifier', message);
      }
      setSubmitting(false);
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <div className="w-full max-w-md bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
        <h2 className="text-2xl font-bold text-center text-gray-700 dark:text-gray-200 mb-6">
          Reset Your Password
        </h2>
        <form onSubmit={formik.handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="identifier" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              SID or Email
            </label>
            <InputText
              id="identifier"
              name="identifier"
              value={formik.values.identifier}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.identifier && formik.errors.identifier ? 'p-invalid' : ''}`}
              placeholder="Enter SID or Email"
            />
            {formik.touched.identifier && formik.errors.identifier && (
              <span className="text-red-500 text-sm">{formik.errors.identifier}</span>
            )}
          </div>
          <Button
            type="submit"
            label={formik.isSubmitting ? 'Requesting...' : 'Request Reset Link'}
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

export default PasswordReset;