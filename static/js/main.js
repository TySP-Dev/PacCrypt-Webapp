/**
 * Main application entry point.
 * Initializes UI and game components when the DOM is loaded.
 */

import { setupUI } from './ui.js';
import { setupGame } from './pacman.js';

// Initialize application when DOM is fully loaded
window.addEventListener("DOMContentLoaded", () => {
    setupUI();
    setupGame();
});
