export const API_ENDPOINTS = {
    LOGIN: '/accounts/login/',
    REGISTER: '/accounts/create-user/',
    PROFILE: (sid) => `/accounts/user-profile/${sid}/`,
    USER_DETAIL: (sid) => `/accounts/users/${sid}/`,
    PASSWORD_CHANGE: '/accounts/password/change/',
    PASSWORD_RESET_REQUEST: '/accounts/password/reset/request/',
    PASSWORD_RESET_CONFIRM: '/accounts/password/reset/confirm/',
    LOGOUT: '/accounts/logout/',
  };
  
  export const REGEX = {
    EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    SID: /^S-1-5-21-\d{10}-\d{10}-\d{10}-\d{4}$/,
    PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  };
