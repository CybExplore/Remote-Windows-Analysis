import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../context/AuthContext';
import { InputText } from 'primereact/inputtext';
import { Button } from 'primereact/button';
import { Password } from 'primereact/password';
import { Divider } from 'primereact/divider';
import { Card } from 'primereact/card';
import { Message } from 'primereact/message';
import { REGEX } from '../utils/constants';
import { classNames } from 'primereact/utils';

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
        .test('is-valid-identifier', 'Invalid SID or Email format', (value) =>
          REGEX.EMAIL.test(value) || REGEX.SID.test(value)
        ),
    }),
    onSubmit: async (values, { setSubmitting, setStatus }) => {
      const { success, message } = await requestPasswordReset(values.identifier);
      setStatus({ success, message });
      setSubmitting(false);
    },
  });

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-gray-800 dark:to-gray-900 p-4">
      <Card className="w-full max-w-md shadow-xl rounded-xl overflow-hidden">
        <div className="p-6">
          <div className="text-center mb-6">
            <i className="pi pi-lock text-5xl text-indigo-600 dark:text-indigo-400 mb-3" />
            <h2 className="text-2xl font-bold text-gray-800 dark:text-white">
              Reset Your Password
            </h2>
            <p className="text-gray-600 dark:text-gray-300 mt-2">
              Enter your SID or email to receive a password reset link
            </p>
          </div>

          {formik.status?.message && (
            <Message
              severity={formik.status.success ? 'success' : 'error'}
              text={formik.status.message}
              className="mb-4"
            />
          )}

          <form onSubmit={formik.handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="identifier" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                SID or Email Address
              </label>
              <span className="p-float-label">
                <InputText
                  id="identifier"
                  name="identifier"
                  value={formik.values.identifier}
                  onChange={formik.handleChange}
                  onBlur={formik.handleBlur}
                  className={classNames('w-full', {
                    'p-invalid': formik.touched.identifier && formik.errors.identifier
                  })}
                  placeholder="S-1-5-21... or user@domain.com"
                />
                {formik.touched.identifier && formik.errors.identifier && (
                  <small className="p-error">{formik.errors.identifier}</small>
                )}
              </span>
            </div>

            <Button
              type="submit"
              label={formik.isSubmitting ? 'Sending Reset Link...' : 'Send Reset Link'}
              icon={formik.isSubmitting ? 'pi pi-spinner pi-spin' : 'pi pi-send'}
              disabled={formik.isSubmitting}
              className="w-full"
              rounded
            />
          </form>

          <Divider align="center" className="my-4">
            <span className="text-sm text-gray-500 dark:text-gray-400">OR</span>
          </Divider>

          <div className="flex justify-center">
            <Button
              label="Back to Login"
              icon="pi pi-arrow-left"
              className="p-button-text text-indigo-600 dark:text-indigo-400"
              onClick={() => navigate('/login')}
            />
          </div>
        </div>

        <div className="bg-gray-50 dark:bg-gray-700 px-6 py-4 text-center">
          <p className="text-sm text-gray-600 dark:text-gray-300">
            Need help?{' '}
            <a href="#" className="text-indigo-600 dark:text-indigo-400 hover:underline">
              Contact support
            </a>
          </p>
        </div>
      </Card>
    </div>
  );
};

export default PasswordReset;