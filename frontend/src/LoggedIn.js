import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import './LoggedIn.css';

const LoggedIn = ({ handleLogout, onStartGame }) => {
    const [gameStarted, setGameStarted] = useState(false);

    const startGame = () => {
        setGameStarted(true);
        onStartGame(); // Signal the parent component to start the game
    };

    return (
        <div>
            
        </div>
    );
};

export default LoggedIn;
