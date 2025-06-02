import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useContext } from 'react';
import { AuthContext } from './context/AuthContext';
import Login from './components/Login';
import Register from './components/Register';
import ChangePassword from './components/ChangePassword';
import Dashboard from './components/Dashboard';
import Navbar from './components/Navbar';
import SecurityEvents from './components/SecurityEvents';
import UserAccount from './components/UserAccount';
import UserGroups from './components/UserGroups';
import UserProfile from './components/UserProfile';
import UserSessions from './components/UserSessions';
import EnvironmentInfo from './components/EnvironmentInfo';
import ProcessLogs from './components/ProcessLogs';
import NetworkLogs from './components/NetworkLogs';
import FileLogs from './components/FileLogs';

function App() {
  const { user, isFirstLogin } = useContext(AuthContext);

  const ProtectedRoute = ({ children, allowFirstLogin = false }) => {
    if (!user) {
      return <Navigate to="/login" />;
    }
    if (isFirstLogin && !allowFirstLogin) {
      return <Navigate to="/change-password" />;
    }
    return children;
  };

  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        {user && <Navbar />}
        <Routes>
          <Route path="/login" element={!user ? <Login /> : <Navigate to={isFirstLogin ? "/change-password" : "/dashboard"} />} />
          <Route path="/register" element={!user ? <Register /> : <Navigate to={isFirstLogin ? "/change-password" : "/dashboard"} />} />
          <Route
            path="/change-password"
            element={
              <ProtectedRoute allowFirstLogin={true}>
                <ChangePassword />
              </ProtectedRoute>
            }
          />
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/security-events"
            element={
              <ProtectedRoute>
                <SecurityEvents />
              </ProtectedRoute>
            }
          />
          <Route
            path="/user-account"
            element={
              <ProtectedRoute>
                <UserAccount />
              </ProtectedRoute>
            }
          />
          <Route
            path="/user-groups"
            element={
              <ProtectedRoute>
                <UserGroups />
              </ProtectedRoute>
            }
          />
          <Route
            path="/user-profile"
            element={
              <ProtectedRoute>
                <UserProfile />
              </ProtectedRoute>
            }
          />
          <Route
            path="/user-sessions"
            element={
              <ProtectedRoute>
                <UserSessions />
              </ProtectedRoute>
            }
          />
          <Route
            path="/environment-info"
            element={
              <ProtectedRoute>
                <EnvironmentInfo />
              </ProtectedRoute>
            }
          />
          <Route
            path="/process-logs"
            element={
              <ProtectedRoute>
                <ProcessLogs />
              </ProtectedRoute>
            }
          />
          <Route
            path="/network-logs"
            element={
              <ProtectedRoute>
                <NetworkLogs />
              </ProtectedRoute>
            }
          />
          <Route
            path="/file-logs"
            element={
              <ProtectedRoute>
                <FileLogs />
              </ProtectedRoute>
            }
          />
          <Route path="*" element={<Navigate to={user ? (isFirstLogin ? "/change-password" : "/dashboard") : "/login"} />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;