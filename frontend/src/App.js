import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import './App.css';
import LandingPage from './LandingPage';
import Game from './Game';
import RegisterModal from './RegisterModule';

const App = () => {
  const logout = () => {
    localStorage.removeItem('token');
    window.location.href = '/';
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
