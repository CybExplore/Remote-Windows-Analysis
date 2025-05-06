import React from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../context/AuthContext';
import { InputText } from 'primereact/inputtext';
import { Password } from 'primereact/password';
import { Button } from 'primereact/button';
import { REGEX } from '../utils/constants';
import { motion } from 'framer-motion';

import imgLogo from '../images/cybexplore.png';

const Login = () => {
  const { login } = useAuth();
  const navigate = useNavigate();

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
      } else {
        navigate('/');
      }
      setSubmitting(false);
    },
  });

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <motion.div
        initial={{ opacity: 0, y: 40 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6 }}
        className="w-full max-w-md bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-8 transition-all duration-500"
      >
        <div className="text-center">
          <img
            alt="Your Company"
            src={imgLogo}
            className="mx-auto h-15 w-auto"
          />
          <h2 className="mt-6 text-2xl font-bold tracking-tight text-gray-900 dark:text-white">
            Sign in to your account
          </h2>
        </div>

        <form onSubmit={formik.handleSubmit} className="mt-8 space-y-6">
          <div>
            <label htmlFor="identifier" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              SID or Email
            </label>
            <div className="mt-2">
              <InputText
                id="identifier"
                name="identifier"
                value={formik.values.identifier}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                className={`w-full rounded-md px-3 py-2 shadow-sm text-base placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:bg-gray-700 dark:text-white transition ${
                  formik.touched.identifier && formik.errors.identifier ? 'p-invalid border-red-500' : ''
                }`}
                placeholder="Enter your SID or email"
              />
              {formik.touched.identifier && formik.errors.identifier && (
                <p className="text-sm text-red-500 mt-1">{formik.errors.identifier}</p>
              )}
            </div>
          </div>

          <div>
            <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300">
              Password
            </label>
            <div className="mt-2">
              <Password
                id="password"
                name="password"
                value={formik.values.password}
                onChange={formik.handleChange}
                onBlur={formik.handleBlur}
                className={`w-full rounded-md px-3 py-2 shadow-sm text-base placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:bg-gray-700 dark:text-white transition ${
                  formik.touched.password && formik.errors.password ? 'p-invalid border-red-500' : ''
                }`}
                placeholder="Enter your password"
                toggleMask
              />
              {formik.touched.password && formik.errors.password && (
                <p className="text-sm text-red-500 mt-1">{formik.errors.password}</p>
              )}
            </div>
          </div>

          <div>
            <Button
              type="submit"
              label={formik.isSubmitting ? 'Logging in...' : 'Sign in'}
              disabled={formik.isSubmitting}
              className="w-full p-button-primary h-10 rounded-md text-white bg-indigo-600 hover:bg-indigo-500 shadow-md transition duration-300"
            />
          </div>
        </form>

        <p className="mt-6 text-center text-sm text-gray-500 dark:text-gray-300">
          <Link to="/password/reset/request" className="font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400">
            Forgot password?
          </Link>
          <span className="mx-2">|</span>
          <a
            href="http://localhost:8000/media/Client.exe"
            className="font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
            download
          >
            Download the Client
          </a>
        </p>
      </motion.div>
    </div>
  );
};

export default Login;
