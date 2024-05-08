import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import axios from 'axios';

// Define environment variables
const CLIENT_ID = process.env.REACT_APP_CLIENT_ID;
const REDIRECT_URI = process.env.REACT_APP_REDIRECT_URI;

const LandingPage = () => {
  // State variables
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loggedIn, setLoggedIn] = useState(false);
  const [gameStarted, setGameStarted] = useState(false);
  const [captchaValue, setCaptchaValue] = useState(null);

  // Function to handle Google sign-in
  const handleGoogleSignIn = () => {
    // Redirect to Google OAuth2 authentication
    window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=token&scope=https://www.googleapis.com/auth/drive.metadata.readonly&include_granted_scopes=true&state=try_sample_request`;
  };

  // Function to redirect to the game page with the token
  const redirectToGame = (token) => {
    // Append the token as a query parameter to the game URI
    const gameUrl = `/game?token=${encodeURIComponent(token)}`;
    // Redirect the user to the game page
    window.location.href = gameUrl;
  };

  // Function to handle user login
  const handleLogin = async () => {
    try {
      // Validate CAPTCHA
      if (!captchaValue) {
        setMessage('Please complete the CAPTCHA.');
        return;
      }
  
      // Send login request to the server
      const response = await axios.post('http://localhost:5000/api/login', {
        email,
        password,
        recaptchaResponse: captchaValue,
      });
      
      // Handle server response
      const { token } = response.data;
      if (token) {
        // Store the hashed token in local storage
        localStorage.setItem('hashedToken', token);
        console.log('Hashed Access Token:', token); 

        // Set logged-in state
        setLoggedIn(true);
        
        // Redirect to the game page with the token
        redirectToGame(token); 
      }
    } catch (error) {
      setMessage('Authentication failed: username or password was incorrect');
    }
  };

  // Define the logout function
  const handleLogout = () => {
    localStorage.removeItem('token');
    setLoggedIn(false);
    window.location.href = '/';
  };

  // Function to handle starting the game
  const handleStartGame = () => {
    setGameStarted(true);
  };

  return (
    <div className="container">
      <h1>The Jumping Journey of Squiggles the Octopus</h1>
      <form>
        {/* Form inputs and buttons */}
        <p>Your email:</p>
        <input
          type="text"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="modal-input"
        />
        <p>Your password:</p>
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="modal-input"
        />
        <ReCAPTCHA
          sitekey="6LcHELQpAAAAAD3k2ZV6xR9MYJAUDdsfBTaeu1Gc"
          onChange={(value) => setCaptchaValue(value)}
        />
        {!loggedIn && (
          <>
            <p style={{ fontFamily: 'Georgia' }}>
              Don't have an account? Register{' '}
              <Link to="/register" className="register-link">here</Link>
            </p>
            <button type="button" onClick={handleLogin}>Login</button>
            <button type="button" onClick={handleGoogleSignIn}>Sign in with Google</button>
          </>
        )}
      </form>
      {message && <p className="message">{message}</p>}
    </div>
  );
};

export default LandingPage;
