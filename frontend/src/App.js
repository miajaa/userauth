import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import LandingPage from './LandingPage';
import Game from './Game';
import RegisterModal from './RegisterModule';
import axios from 'axios';


const App = () => {
  
const LOGOUT_ENDPOINT = process.env.REACT_APP_LOGOUT_ENDPOINT

  const logout = async () => {
    try {
      const token = localStorage.getItem('token');
      if (token) {
        // Make a POST request to the logout endpoint
        await axios.post(LOGOUT_ENDPOINT, {
          token: token
        });
      }
      // Remove token from local storage
      localStorage.removeItem('token');
      // Redirect to the home page
      window.location.href = '/';
    } catch (error) {
      console.error('Logout failed:', error);
    }
  };
  

  return (
    <Router>
      <Routes>
        <Route path="/" element={<LandingPage logout={logout} />} />
        <Route path="/game" element={<Game logout={logout} />} />
        <Route path="/register" element={<RegisterModal />} />
      </Routes>
    </Router>
  );
};

export default App;
