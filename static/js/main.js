// main.js

import { setupUI } from './ui.js';
import { setupGame } from './pacman.js';

/**
 * Initialize UI and game once the DOM is fully loaded.
 */
window.addEventListener("DOMContentLoaded", () => {
    setupUI();
    setupGame();
});
