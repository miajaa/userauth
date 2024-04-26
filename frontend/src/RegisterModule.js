import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import axios from 'axios';
import './RegisterModule.css';

const RegisterModal = ({ handleClose }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [captchaValue, setCaptchaValue] = useState('');
  const [message, setMessage] = useState('');

  const handleRegister = async () => {
    try {
      if (!captchaValue) {
        setMessage('Please complete the CAPTCHA.');
        return;
      }
  
      if (password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[!@#$%^&*()-_=+{};:,.]/.test(password)) {
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
      } else if (response.data.error === 'User already exists') {
        setMessage('User already exists'); // Display user exists error
      } else {
        setMessage('Registration failed: Unexpected response from server');
      }
    } catch (error) {
      console.error('Registration error:', error);
      setMessage('Registration failed: An error occurred');
    }
  };
  

  const handleSubmit = async () => {
    await handleRegister(); // Call the handleRegister function for registration
  };

  return (
    <div className="register-page">
      <div className="register-content-container">
        <div className="register-content">
          <Link to="/" className="close-button">[X] Back</Link>
          <h2>Register</h2>
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
          {message && <p>{message}</p>}
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <ReCAPTCHA
            sitekey="6LcHELQpAAAAAD3k2ZV6xR9MYJAUDdsfBTaeu1Gc"
            onChange={(value) => setCaptchaValue(value)}
            className="modal-recaptcha"
          />
          <button onClick={handleSubmit} className="modal-button" style={{ marginTop: '10px' }}>Register</button>
        </div>
      </div>
    </div>
  );
};

export default RegisterModal;
