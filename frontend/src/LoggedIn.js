import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import './LoggedIn.css';

const LoggedIn = ({ handleLogout, onStartGame }) => {
    const [gameStarted, setGameStarted] = useState(false);

    const startGame = () => {
        setGameStarted(true);
        onStartGame(); 
    };

    return (
        <div>
            
        </div>
    );
};

export default LoggedIn;
