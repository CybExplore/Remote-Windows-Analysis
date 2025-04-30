import React from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../context/AuthContext';
import { InputText } from 'primereact/inputtext';
import { Password } from 'primereact/password';
import { Button } from 'primereact/button';
import { REGEX } from '../utils/constants';

const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();
  console.log(navigate);

  const formik = useFormik({
    initialValues: {
      identifier: '',
      password: '',
    },
    validationSchema: Yup.object({
      identifier: Yup.string()
        .required('SID or Email is required')
        .test('is-valid-identifier', 'Invalid SID or Email', (value) =>
          REGEX.EMAIL.test(value) || REGEX.SID.test(value)
        ),
      password: Yup.string().required('Password is required'),
    }),
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      const { success, message } = await login(values.identifier, values.password);
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
          Login to Remote Windows Security
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
          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Password
            </label>
            <Password
              id="password"
              name="password"
              value={formik.values.password}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.password && formik.errors.password ? 'p-invalid' : ''}`}
              placeholder="Enter Password"
              toggleMask
            />
            {formik.touched.password && formik.errors.password && (
              <span className="text-red-500 text-sm">{formik.errors.password}</span>
            )}
          </div>
          <Button
            type="submit"
            label={formik.isSubmitting ? 'Logging in...' : 'Login'}
            disabled={formik.isSubmitting}
            className="w-full p-button-raised p-button-primary"
          />
        </form>
        <div className="mt-4 text-center">
          <Link to="/password/reset/request" className="text-indigo-600 dark:text-indigo-400 hover:underline">
            Forgot Password?
          </Link>
          <span className="mx-2 text-gray-600 dark:text-gray-300">|</span>
          <a 
            href="http://localhost:8000/media/Client.exe" 
            className="text-indigo-600 dark:text-indigo-400 hover:underline"
            download
          >
            Download The Client
          </a>
        </div>
      </div>
    </div>
  );
};

export default Login;
