import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import axios from 'axios';

const CLIENT_ID = process.env.REACT_APP_CLIENT_ID;
const REDIRECT_URI = process.env.REACT_APP_REDIRECT_URI;
const LOGIN_ENDPOINT = process.env.REACT_APP_LOGIN_ENDPOINT;

const LandingPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loggedIn, setLoggedIn] = useState(false);
  const [captchaValue, setCaptchaValue] = useState(null);

  const handleGoogleSignIn = () => {
    window.location.href = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&response_type=token&scope=https://www.googleapis.com/auth/drive.metadata.readonly&include_granted_scopes=true&state=try_sample_request`;
  };

  const redirectToGame = (token) => {
    const gameUrl = `/game?token=${encodeURIComponent(token)}`;
    window.location.href = gameUrl;
  };

  const handleLogin = async () => {
    try {
      if (!captchaValue) {
        setMessage('Please complete the CAPTCHA.');
        return;
      }

      const response = await axios.post(LOGIN_ENDPOINT, {
        email,
        password,
        recaptchaResponse: captchaValue,
      });

      const { token } = response.data;
      if (token) {
        localStorage.setItem('hashedToken', token);
        console.log('Hashed Access Token:', token);

        setLoggedIn(true);

        // Check if the token is valid
      const isAuthenticated = await checkAuthentication();
      if (isAuthenticated) {
        redirectToGame(token);
      } else {
        setMessage('Authentication failed: Invalid token');
        setLoggedIn(false);
      }
      }
    } catch (error) {
      if (error.response && error.response.data && error.response.data.error) {
        setMessage(error.response.data.error);
      } else {
        setMessage('Authentication failed: username or password was incorrect');
      }
    }
  };

  const checkAuthentication = async () => {
    try {
      const token = localStorage.getItem('hashedToken');
      if (!token) {
        return false; // No token found in localStorage, user is not authenticated
      }
      console.log('Token retrieved from localstorage: ', token)
      // Send a request to the backend to validate the token
      const response = await axios.post('http://localhost:3002/api/check-token', { token });
  
      // If the response status is 200 and the token is valid, return true
      return response.data.valid === true;
    } catch (error) {
      console.error('Error checking authentication:', error);
      return false; // Error occurred during token validation
    }
  };

  return (
    <div className="container">
      <h1>The Jumping Journey of Squiggles the Octopus</h1>
      <form>
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
