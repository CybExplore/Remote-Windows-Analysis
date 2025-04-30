export const API_ENDPOINTS = {
    LOGIN: '/login/',
    REGISTER: '/create-user/',
    PROFILE: (sid) => `/profile/${sid}/`,
    USER_DETAIL: (sid) => `/users/${sid}/`,
    PASSWORD_CHANGE: '/password/change/',
    PASSWORD_RESET_REQUEST: '/password/reset/request/',
    PASSWORD_RESET_CONFIRM: '/password/reset/confirm/',
    EMAIL_VERIFY: '/email/verify/',
    EMAIL_VERIFY_CONFIRM: '/email/verify/confirm/',
    LOGOUT: '/logout/',
  };
  
  export const REGEX = {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    SID: /^S-1-5-21-\d{10}-\d{10}-\d{10}-\d{4}$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  };
