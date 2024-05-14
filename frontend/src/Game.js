import React, { useState, useEffect } from 'react';
import './Game.css';

const Game = ({ logout }) => {
  const [jumping, setJumping] = useState(false);
  const [isGameOver, setIsGameOver] = useState(false);
  const [blockPosition, setBlockPosition] = useState({ top: 270, left: 750 });
  const [blockInterval, setBlockInterval] = useState(null);
  const [gameStarted, setGameStarted] = useState(false); // State variable to track if the game has started

  useEffect(() => {
    const handleKeyPress = (event) => {
      if (event.code === 'Space') {
        // Call the handleJump function when space bar is pressed
        handleJump();
      }
    };

    document.addEventListener('keydown', handleKeyPress);

    return () => {
      document.removeEventListener('keydown', handleKeyPress);
    };
  }, []);

  useEffect(() => {
    if (gameStarted && !isGameOver) { // Start the block movement only if the game has started
      setBlockInterval(setInterval(() => {
        setBlockPosition(prevPosition => {
          const newPosition = { ...prevPosition, left: prevPosition.left - 2 };
          if (newPosition.left <= -20) {
            newPosition.left = 750; // Set it to the rightmost position
          }
          return newPosition;
        });
      }, 5));
    }

    const checkDead = setInterval(() => {
      if (!jumping && !isGameOver && gameStarted) { // Check for collision only if the game has started
        checkCollision();
      }
    }, 10);

    return () => {
      clearInterval(checkDead);
      clearInterval(blockInterval);
    };
  }, [jumping, isGameOver, gameStarted]);

  const handleJump = () => {
    if (!jumping && !isGameOver && gameStarted) { // Allow jumping only if the game has started
      setJumping(true);
      setTimeout(() => {
        setJumping(false);
      }, 500);
      jump();
    }
  };

  const handleCollision = () => {
    setIsGameOver(true);
  };

  const handleRestartGame = () => {
    setIsGameOver(false);
    setBlockPosition({ top: 270, left: 750 });
  };

  const handleStartGame = () => {
    setGameStarted(true); // Set the game started state to true when the Start Game button is clicked
  };

  const handleLogout = () => {
    logout();
  };

  const jump = () => {
    const character = document.getElementById("character");
    if (!character.classList.contains("animate")) {
      character.classList.add("animate");
      setTimeout(() => {
        character.classList.remove("animate");
        character.style.top = "60%"; // Set the character back to its original position
      }, 500);
    }
  };

  const checkCollision = () => {
    const characterRect = document.getElementById("character").getBoundingClientRect();
    const blockRect = document.getElementById("block").getBoundingClientRect();

    if (
      characterRect.left < blockRect.right &&
      characterRect.right > blockRect.left &&
      characterRect.top < blockRect.bottom &&
      characterRect.bottom > blockRect.top
    ) {
      handleCollision();
    }
  };

  return (
    <div id="game" className={isGameOver ? "over" : ""} onClick={handleJump}>
      <div className="game-content">
        {gameStarted && (
          <>
            <div id="character"></div>
            <div id="block" className="block" style={{ top: blockPosition.top, left: blockPosition.left }}></div>
            {isGameOver && (
              <div className="game-over-container">
                <div className="game-over">
                  <p>Game Over</p>
                  <div className="game-over-buttons">
                    <button onClick={handleRestartGame}>Restart Game</button>
                    <button onClick={handleLogout}>Logout</button>
                  </div>
                </div>
              </div>
            )}
          </>
        )}
        {!gameStarted && (
          <div className="start-game-container">
            <button onClick={handleStartGame}>Start Game</button>
            <button onClick={handleLogout}>Logout</button>
          </div>
        )}
      </div>
    </div>
  );
  
  
  
};

export default Game;
