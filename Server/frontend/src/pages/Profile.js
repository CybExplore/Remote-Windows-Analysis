import React from 'react';
import { useFormik } from 'formik';
import * as Yup from 'yup';
import { useAuth } from '../context/AuthContext';
import { InputText } from 'primereact/inputtext';
import { Button } from 'primereact/button';
import { Card } from 'primereact/card';

const Profile = () => {
  const { user, updateProfile } = useAuth();

  const formik = useFormik({
    initialValues: {
      full_name: user?.full_name || '',
      email: user?.email || '',
      department: user?.profile?.department || '',
      job_title: user?.profile?.job_title || '',
      description: user?.profile?.description || '',
    },
    validationSchema: Yup.object({
      full_name: Yup.string().required('Full name is required'),
      email: Yup.string().email('Invalid email').required('Email is required'),
      department: Yup.string(),
      job_title: Yup.string(),
      description: Yup.string(),
    }),
    onSubmit: async (values, { setSubmitting, setFieldError }) => {
      const profileData = {
        department: values.department,
        job_title: values.job_title,
        description: values.description,
      };
      const { success, message } = await updateProfile(user.sid, profileData);
      if (!success) {
        setFieldError('description', message);
      }
      setSubmitting(false);
    },
  });

  return (
    <div className="container mx-auto px-4 py-8">
      <h2 className="text-3xl font-bold text-gray-700 dark:text-gray-200 mb-6">Profile</h2>
      <Card className="bg-white dark:bg-gray-800 shadow-md max-w-2xl mx-auto">
        <form onSubmit={formik.handleSubmit} className="space-y-6">
          <div>
            <label htmlFor="full_name" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Full Name
            </label>
            <InputText
              id="full_name"
              name="full_name"
              value={formik.values.full_name}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.full_name && formik.errors.full_name ? 'p-invalid' : ''}`}
              disabled
            />
            {formik.touched.full_name && formik.errors.full_name && (
              <span className="text-red-500 text-sm">{formik.errors.full_name}</span>
            )}
          </div>
          <div>
            <label htmlFor="email" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Email
            </label>
            <InputText
              id="email"
              name="email"
              value={formik.values.email}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.email && formik.errors.email ? 'p-invalid' : ''}`}
              disabled
            />
            {formik.touched.email && formik.errors.email && (
              <span className="text-red-500 text-sm">{formik.errors.email}</span>
            )}
          </div>
          <div>
            <label htmlFor="department" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Department
            </label>
            <InputText
              id="department"
              name="department"
              value={formik.values.department}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.department && formik.errors.department ? 'p-invalid' : ''}`}
            />
            {formik.touched.department && formik.errors.department && (
              <span className="text-red-500 text-sm">{formik.errors.department}</span>
            )}
          </div>
          <div>
            <label htmlFor="job_title" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Job Title
            </label>
            <InputText
              id="job_title"
              name="job_title"
              value={formik.values.job_title}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.job_title && formik.errors.job_title ? 'p-invalid' : ''}`}
            />
            {formik.touched.job_title && formik.errors.job_title && (
              <span className="text-red-500 text-sm">{formik.errors.job_title}</span>
            )}
          </div>
          <div>
            <label htmlFor="description" className="block text-sm font-medium text-gray-600 dark:text-gray-300">
              Description
            </label>
            <InputText
              id="description"
              name="description"
              value={formik.values.description}
              onChange={formik.handleChange}
              onBlur={formik.handleBlur}
              className={`w-full mt-1 ${formik.touched.description && formik.errors.description ? 'p-invalid' : ''}`}
            />
            {formik.touched.description && formik.errors.description && (
              <span className="text-red-500 text-sm">{formik.errors.description}</span>
            )}
          </div>
          <Button
            type="submit"
            label={formik.isSubmitting ? 'Updating...' : 'Update Profile'}
            disabled={formik.isSubmitting}
            className="w-full p-button-raised p-button-primary"
          />
        </form>
      </Card>
    </div>
  );
};

export default Profile;