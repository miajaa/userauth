import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import LandingPage from './LandingPage';
import Game from './Game';
import RegisterModal from './RegisterModule';

const App = () => {
  // Initialize token state with null
  const [token, setToken] = useState(null);

  const logout = () => {
    localStorage.removeItem('token');
    setToken(null); // Clear token when logging out
    window.location.href = '/';
  };

  // Function to handle registration success and update token state
  const handleRegistrationSuccess = (token) => {
    setToken(token);
  };

  return (
    <Router>
      <Routes>
        <Route path="/" element={<LandingPage logout={logout} />} />
        <Route path="/game" element={<Game logout={logout} />} />
        {/* Pass token state and update function to RegisterModal */}
        <Route
          path="/register"
          element={<RegisterModal token={token} onRegistrationSuccess={handleRegistrationSuccess} />}
        />
      </Routes>
    </Router>
  );
};

export default App;
