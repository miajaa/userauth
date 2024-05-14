import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import axios from 'axios';

const CLIENT_ID = process.env.REACT_APP_CLIENT_ID;
const REDIRECT_URI = process.env.REACT_APP_REDIRECT_URI;
const LOGIN_ENDPOINT = process.env.REACT_APP_LOGIN_ENDPOINT;
const CHECK_TOKEN_ENDPOINT = process.env.REACT_APP_CHECK_TOKEN_ENDPOINT
const LOGOUT_ENDPOINT = process.env.REACT_APP_LOGOUT_ENDPOINT

const LandingPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loggedIn, setLoggedIn] = useState(false);
  const [gameStarted, setGameStarted] = useState(false);
  const [captchaValue, setCaptchaValue] = useState(null);

  const handleGoogleSignIn = () => {
    // Redirect to Google OAuth2 authentication
    window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=token&scope=https://www.googleapis.com/auth/drive.metadata.readonly&include_granted_scopes=true&state=try_sample_request`;
  };

  const redirectToGame = (token) => {
    const gameUrl = `/game?token=${encodeURIComponent(token)}`;
    window.location.href = gameUrl;
  };

  
  const handleLogin = async () => {
    try {
      if (!captchaValue || !email ||!password) {
        setMessage('Please complete the CAPTCHA and make sure no field is empty.');
        return;
      }
  
      const response = await axios.post(LOGIN_ENDPOINT, {
        email,
        password,
        recaptchaResponse: captchaValue,
      });
  
      // Check if the token is valid
      const isAuthenticated = await checkAuthentication(response.data.token);
      if (isAuthenticated) {
        localStorage.setItem('token', response.data.token);
        setMessage('Login successful');
        setLoggedIn(true);
        
        // Redirect to game
        redirectToGame();
      } else {
        setMessage('Authentication failed: Invalid token');
      }
    } catch (error) {
      setMessage('Authentication failed: username or password was incorrect');
    }
  };

  const checkAuthentication = async (token) => {
    try {
      // Send a request to the backend to validate the token
      const response = await axios.post(CHECK_TOKEN_ENDPOINT, { token });
  
      // If the response status is 200 and the token is valid, return true
      return response.data.valid === true;
    } catch (error) {
      console.error('Error checking authentication:', error);
      return false; // Error occurred during token validation
    }
  };
  

  const handleLogout = async () => {
    try {
      // Get the token from local storage
      const token = localStorage.getItem('token');
      if (!token) {
        // Token not found in local storage
        setLoggedIn(false);
        return;
      }
  
      // Make a POST request to the logout endpoint
      const response = await axios.post(LOGOUT_ENDPOINT , {
        token: token
      });
  
      // Check if the logout was successful
      if (response.status === 200) {
        // Remove token from local storage
        localStorage.removeItem('token');
        // Update state to indicate user is logged out
        setLoggedIn(false);
        // Redirect to home page
        window.location.href = '/';
      } else {
        // Handle unsuccessful logout
        console.error('Logout failed:', response.data.error);
        // You can display an error message to the user if needed
      }
    } catch (error) {
      console.error('Error during logout:', error);
      // Handle error if the logout request fails
    }
  };
  

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
        {loggedIn && (
          <div>
            <button onClick={handleLogout}>Logout</button>
            {!gameStarted ? (
              <button onClick={handleStartGame}>Start Game</button>
            ) : (
              <Link to="/game">Play Game</Link>
            )}
          </div>
        )}
      </form>
      {message && <p className="message">{message}</p>}
    </div>
  );
};

export default LandingPage;