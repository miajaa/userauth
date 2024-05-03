
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import ReCAPTCHA from 'react-google-recaptcha';
import axios from 'axios';
import './RegisterModule.css';

const RegisterModal = ({ token }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [retypePassword, setRetypePassword] = useState('');
  const [captchaValue, setCaptchaValue] = useState('');
  const [message, setMessage] = useState('');
  const [showPopup, setShowPopup] = useState(false);

  const handleRegister = async () => {
    try {
      console.log("Token Prop Value:", token);
      if (password !== retypePassword) {
        setMessage('Passwords do not match.');
        return false; // Return unsuccessful
      }

      if (password.length < 8 || !/[a-z]/.test(password) || !/[A-Z]/.test(password) || !/\d/.test(password) || !/[!@#$%^&*()-_=+{};:,.]/.test(password)) {
        setMessage('Password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character.');
        return false; // Return unsuccessful
      }

      const response = await axios.post('http://localhost:5000/api/register', {
        email,
        password,
        recaptchaResponse: captchaValue,
      });

      if (response.data.message === 'User registered successfully') {
        setMessage(response.data.message);
        return true; // Return successful
      }
    } catch (error) {
      if (error.response) {
        // The request was made and the server responded with a status code
        if (error.response.status === 400) {
          // Handle validation errors
          setMessage(error.response.data.error);
        } else if (error.response.status === 409) {
          // Handle user already exists error
          setMessage('User already exists. Please try with a different email.');
        } else if (error.response.status === 422) {
          // Handle email format error
          setMessage('Invalid email format. Please enter a valid email address.');
        } else if (error.response.status === 429) {
          // Handle reCAPTCHA verification failure error
          setMessage('reCAPTCHA verification failed. Please try again.');
        } else if (error.response.status === 500) {
          // Handle server errors
          setMessage('Registration failed: An internal server error occurred');
        } else {
          // Handle other server errors
          setMessage('Registration failed: Unexpected response from server');
        }
      } else if (error.request) {
        // The request was made but no response was received
        setMessage('Registration failed: No response from server');
      } else {
        // Something else happened while setting up the request
        setMessage('Registration failed: An error occurred');
      }
    }
    return false;
  };

  const handleSubmit = async () => {
    if (!email || !password || !retypePassword || !captchaValue) {
      setMessage('Please fill in all fields and complete the CAPTCHA.');
      return;
    }
    const registrationSuccess = await handleRegister();
    if (registrationSuccess) {
      setShowPopup(true);
    }
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
          <p>Repeat password:</p>
          <input
            type="password"
            placeholder="Repeat Password"
            value={retypePassword}
            onChange={(e) => setRetypePassword(e.target.value)}
            className="modal-input"
          />
          {message && <p>{message}</p>}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
            <ReCAPTCHA
              sitekey="6LcHELQpAAAAAD3k2ZV6xR9MYJAUDdsfBTaeu1Gc"
              onChange={(value) => setCaptchaValue(value)}
              className="modal-recaptcha"
            />
            <button onClick={handleSubmit} className="modal-button" style={{ marginTop: '10px' }}>Validate Email</button>
          </div>
        </div>
      </div>
      {showPopup && (
        <div className="popup" style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', zIndex: 999, border: '5px solid #FF69B4', borderRadius: '10px', backgroundColor: '#FDF5E6', boxShadow: '0px 0px 20px rgba(0, 0, 0, 0.3)', display: 'flex', flexDirection: 'column' }}>
          <div style={{ backgroundColor: '#FF69B4', color: '#fff', padding: '20px', borderTopLeftRadius: '10px', borderTopRightRadius: '10px' }}>
            <h2 style={{alignSelf: 'center'}}> Please validate your email</h2>
          </div>
          <div style={{ backgroundColor: '#F9F9F9', padding: '20px', textAlign: 'center' }}>
            <p>The validation email has been sent to the address below</p>
            <p style={{ textAlign: 'center', color: '#6A5ACD'}}>{email}</p>
            <p>To verify your account and embark on the adventurous journey with Squiggles the Octopus, please click the link below:</p>
            <p id="validation-message"></p>
            <Link to={`/game?token=${token}`} onClick={() => setShowPopup(false)} style={{ color: '#FF69B4', textDecoration: 'none', alignSelf: 'center' }}>https://www.jumpingjourneyofsquiggles.com/verify?token={token}</Link>

          </div>
        </div>
      )}



    </div>
  );
};

export default RegisterModal;