import axios from 'axios';

// Request retry configuration
const RETRY_CONFIG = {
  maxRetries: 3,
  retryDelay: 1000,
  retryableStatuses: [408, 429, 500, 502, 503, 504],
};

let authRedirecting = false;

const isRequestCanceled = (error) => (
  error?.name === 'CanceledError' ||
  error?.name === 'AbortError' ||
  error?.code === 'ERR_CANCELED' ||
  error?.message === 'canceled'
);

// Create axios instance with retry logic
const request = axios.create({
  timeout: 30000,
});

// Request interceptor
request.interceptors.request.use(config => {
  const session = localStorage.getItem('session');
  if (session) {
    config.headers.Authorization = session;
  }
  // Initialize retry count
  config.__retryCount = config.__retryCount || 0;
  return config;
});

// Response interceptor with retry logic
request.interceptors.response.use(
  response => {
    if (String(response.config?.url || '').includes('/auth/login')) {
      authRedirecting = false;
    }
    return response;
  },
  async error => {
    const config = error.config;

    if (isRequestCanceled(error)) {
      return Promise.reject(error);
    }

    // Handle an expired session, but never swallow login failures or turn
    // transport/5xx failures into a logout.
    if (error.response?.status === 401) {
      const url = String(config?.url || '');
      const isLoginRequest = url.includes('/auth/login');
      const hasSession = Boolean(localStorage.getItem('session'));
      if (!isLoginRequest && hasSession && !authRedirecting) {
        authRedirecting = true;
        localStorage.removeItem('session');
        window.dispatchEvent(new CustomEvent('session-expired'));
      }
      return Promise.reject(error);
    }

    // Check if we should retry
    const method = config?.method?.toLowerCase() || 'get';
    const isSafeRead = ['get', 'head', 'options'].includes(method);
    const shouldRetry =
      config &&
      isSafeRead &&
      config.__retryCount < RETRY_CONFIG.maxRetries &&
      (
        !error.response ||
        RETRY_CONFIG.retryableStatuses.includes(error.response.status)
      );

    if (shouldRetry) {
      config.__retryCount += 1;

      // Exponential backoff
      const delay = RETRY_CONFIG.retryDelay * Math.pow(2, config.__retryCount - 1);

      console.info(`Retrying request (${config.__retryCount}/${RETRY_CONFIG.maxRetries}) after ${delay}ms`);

      await new Promise(resolve => setTimeout(resolve, delay));

      return request(config);
    }

    return Promise.reject(error);
  }
);

export default request;

// Export retry config for customization
export { RETRY_CONFIG, isRequestCanceled };
