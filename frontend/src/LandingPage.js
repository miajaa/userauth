import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import axios from 'axios';

const CLIENT_ID = '54101202704-gdbicmniaerj0hahatfqu02e6jepmv4g.apps.googleusercontent.com';
const REDIRECT_URI = 'http://localhost:3000/game';

const LandingPage = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [loggedIn, setLoggedIn] = useState(false);
  const [gameStarted, setGameStarted] = useState(false);
  const [captchaValue, setCaptchaValue] = useState(null);

  const handleRegister = async () => {
    try {
      if (!captchaValue) {
        setMessage('Please complete the CAPTCHA.');
        return;
      }

      if (password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[!@#$%^&*()-_=+{};:,<.>]/.test(password)) {
        setMessage('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.');
        return;
      }

      const response = await axios.post('http://localhost:5000/api/register', {
        email,
        password,
        recaptchaResponse: captchaValue,
      });

      if (response.data.message) {
        setMessage(response.data.message);
      } else {
        setMessage('Registration failed: Unexpected response from server');
      }
    } catch (error) {
      console.error('Registration error:', error);
      setMessage('Registration failed: An error occurred');
    }
  };

  const redirectToGame = () => {
    window.location.href = '/game';
  };

  const handleLogin = async () => {
    try {
      if (!captchaValue) {
        setMessage('Please complete the CAPTCHA.');
        return;
      }
  
      const response = await axios.post('http://localhost:5000/api/login', {
        email,
        password,
        recaptchaResponse: captchaValue,
      });
  
      localStorage.setItem('token', response.data.token);
      setMessage('Login successful');
      setLoggedIn(true);
      
      // Redirect to game
      redirectToGame();
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

  const handleStartGame = () => {
    setGameStarted(true);
  };

  const trySampleRequest = () => {
    var xhr = new XMLHttpRequest();
    xhr.open('GET',
      'https://www.googleapis.com/drive/v3/about?fields=user&' +
      'access_token=' + localStorage.getItem('access_token'));
    xhr.onreadystatechange = function (e) {
      if (xhr.readyState === 4 && xhr.status === 200) {
        console.log(xhr.response);
      } else if (xhr.readyState === 4 && xhr.status === 401) {
        // Token invalid, so prompt for user permission.
        oauth2SignIn();
      }
    };
    xhr.send(null);
  };

  const oauth2SignIn = () => {
    const oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';

    const params = {
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      response_type: 'token',
      scope: 'https://www.googleapis.com/auth/drive.metadata.readonly',
      include_granted_scopes: 'true',
      state: 'try_sample_request',
    };

    const form = document.createElement('form');
    form.setAttribute('method', 'GET');
    form.setAttribute('action', oauth2Endpoint);

    for (const p in params) {
      const input = document.createElement('input');
      input.setAttribute('type', 'hidden');
      input.setAttribute('name', p);
      input.setAttribute('value', params[p]);
      form.appendChild(input);
    }

    document.body.appendChild(form);
    form.submit();
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
            <button type="button" onClick={oauth2SignIn}>Sign in with Google</button>
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
