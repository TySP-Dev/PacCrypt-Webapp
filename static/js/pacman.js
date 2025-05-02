/**
 * Pacman game module.
 * Handles game logic, rendering, and user interaction.
 */

// ===== Game Constants =====
const PACMAN_SPEED = 40;
const ENEMY_SPEED = 20;
const CELL_SIZE = 40;
const DOT_SIZE = 5;

// ===== Game State =====
let canvas, ctx, pacman, enemy, walls, dots, score;
let cols, rows, randSeed, gameInterval;

// ===== Public Interface =====
export function setupGame() {
    console.log('[PacMan] Game module loaded.');
    window.startPacman = startPacman;
    window.exitGame = exitGame;
}

export function startPacman() {
    initializeGame();
    setupGameLoop();
}

export function stopPacman() {
    clearInterval(gameInterval);
    if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
}

export function resetGame() {
    stopPacman();
    startPacman();
}

export function exitGame() {
    stopPacman();
    document.getElementById("input-text").value = "";
    document.getElementById("pacman-section").style.display = "none";
    document.getElementById("encoding-section").style.display = "block";
}

// ===== Game Initialization =====
function initializeGame() {
    canvas = document.getElementById("pacmanCanvas");
    ctx = canvas.getContext("2d");

    cols = Math.floor(canvas.width / CELL_SIZE);
    rows = Math.floor(canvas.height / CELL_SIZE);
    walls = [];
    dots = [];
    score = 0;

    clearInterval(gameInterval);
    
    // Get seed from generated password or use default
    const passwordField = document.getElementById("generated-password");
    const seedSource = passwordField?.value || "pacman";
    randSeed = [...seedSource].reduce((s, c) => s + c.charCodeAt(0), 0);

    generateWalls();
    generateDots();

    pacman = spawn();
    do { enemy = spawn(); } while (enemy.x === pacman.x && enemy.y === pacman.y);

    pacman.dx = pacman.dy = 0;
    document.addEventListener("keydown", movePacman);
}

function setupGameLoop() {
    gameInterval = setInterval(gameLoop, 150);
}

// ===== Game Setup Helpers =====
function spawn() {
    const options = [];
    for (let c = 1; c < cols - 1; c++) {
        for (let r = 1; r < rows - 1; r++) {
            if (!walls.some(w => w.c === c && w.r === r)) {
                const neighbors = [
                    { c: c + 1, r }, { c: c - 1, r },
                    { c, r: r + 1 }, { c, r: r - 1 }
                ];
                if (neighbors.some(n => !walls.some(w => w.c === n.c && w.r === n.r))) {
                    options.push({ c, r });
                }
            }
        }
    }
    const s = options[Math.floor(rand() * options.length)];
    return {
        x: s.c * CELL_SIZE + CELL_SIZE / 2,
        y: s.r * CELL_SIZE + CELL_SIZE / 2,
        size: CELL_SIZE / 2 - 5,
        dx: 0,
        dy: 0
    };
}

function rand() {
    const x = Math.sin(randSeed++) * 10000;
    return x - Math.floor(x);
}

function generateWalls() {
    // First pass: generate initial walls
    for (let c = 0; c < cols; c++) {
        for (let r = 0; r < rows; r++) {
            if (c === 0 || r === 0 || c === cols - 1 || r === rows - 1 || rand() < 0.2) {
                walls.push({ c, r });
            }
        }
    }

    // Second pass: check for enclosed spaces
    for (let c = 1; c < cols - 1; c++) {
        for (let r = 1; r < rows - 1; r++) {
            // Skip if already a wall
            if (walls.some(w => w.c === c && w.r === r)) continue;

            // Check all four sides
            const hasWallAbove = walls.some(w => w.c === c && w.r === r - 1);
            const hasWallBelow = walls.some(w => w.c === c && w.r === r + 1);
            const hasWallLeft = walls.some(w => w.c === c - 1 && w.r === r);
            const hasWallRight = walls.some(w => w.c === c + 1 && w.r === r);

            // If all sides are walls, make this spot a wall too
            if (hasWallAbove && hasWallBelow && hasWallLeft && hasWallRight) {
                walls.push({ c, r });
            }
        }
    }
}

function generateDots() {
    dots = [];
    for (let c = 1; c < cols - 1; c++) {
        for (let r = 1; r < rows - 1; r++) {
            if (walls.some(w => w.c === c && w.r === r)) continue;

            const isEnclosed =
                walls.some(w => w.c === c + 1 && w.r === r) &&
                walls.some(w => w.c === c - 1 && w.r === r) &&
                walls.some(w => w.c === c && w.r === r + 1) &&
                walls.some(w => w.c === c && w.r === r - 1);

            if (!isEnclosed) dots.push({ c, r });
        }
    }
}

// ===== Game Loop & Rendering =====
function gameLoop() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    drawWalls();
    moveChar(pacman);
    moveEnemy();
    drawChar(pacman, "yellow");
    drawChar(enemy, "red");
    eatDots();
    drawScore();
    checkGameOver();
}

function drawWalls() {
    ctx.fillStyle = "blue";
    walls.forEach(w => {
        ctx.fillRect(w.c * CELL_SIZE, w.r * CELL_SIZE, CELL_SIZE, CELL_SIZE);
    });
}

function drawChar(ch, color) {
    ctx.beginPath();
    ctx.arc(ch.x, ch.y, ch.size, 0, Math.PI * 2);
    ctx.fillStyle = color;
    ctx.fill();
}

function drawScore() {
    ctx.fillStyle = "white";
    ctx.font = "20px Poppins";
    ctx.textAlign = "left";
    // Add padding to prevent clipping
    const padding = 10;
    ctx.fillText("Score: " + score, padding, 25);
}

function checkGameOver() {
    if (
        Math.abs(pacman.x - enemy.x) < pacman.size &&
        Math.abs(pacman.y - enemy.y) < pacman.size
    ) {
        ctx.fillStyle = "#00ff99";
        ctx.font = "40px Poppins";
        ctx.textAlign = "center";
        ctx.fillText("Game Over!", canvas.width / 2, canvas.height / 2);
        clearInterval(gameInterval);
    }
}

// ===== Movement Logic =====
function movePacman(e) {
    const k = e.key;
    if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(k)) return;
    e.preventDefault();

    if (k === "ArrowUp") { pacman.dx = 0; pacman.dy = -PACMAN_SPEED; }
    if (k === "ArrowDown") { pacman.dx = 0; pacman.dy = PACMAN_SPEED; }
    if (k === "ArrowLeft") { pacman.dx = -PACMAN_SPEED; pacman.dy = 0; }
    if (k === "ArrowRight") { pacman.dx = PACMAN_SPEED; pacman.dy = 0; }
}

function moveChar(ch) {
    const nx = ch.x + ch.dx;
    const ny = ch.y + ch.dy;
    if (!willCollide(nx, ny, ch.size)) {
        ch.x = nx;
        ch.y = ny;
    }
}

function moveEnemy() {
    const options = [];
    const moves = [[ENEMY_SPEED, 0], [-ENEMY_SPEED, 0], [0, ENEMY_SPEED], [0, -ENEMY_SPEED]];

    moves.forEach(([dx, dy]) => {
        const nx = enemy.x + dx;
        const ny = enemy.y + dy;
        if (!willCollide(nx, ny, enemy.size)) options.push({ dx, dy });
    });

    if (!options.length) return;

    let best = options[0];
    let bestDist = dist(enemy.x + best.dx, enemy.y + best.dy, pacman.x, pacman.y);

    for (const opt of options) {
        const d = dist(enemy.x + opt.dx, enemy.y + opt.dy, pacman.x, pacman.y);
        if (d < bestDist) {
            best = opt;
            bestDist = d;
        }
    }

    enemy.x += best.dx;
    enemy.y += best.dy;
}

function dist(x1, y1, x2, y2) {
    return Math.abs(x1 - x2) + Math.abs(y1 - y2);
}

function willCollide(x, y, size) {
    const left = x - size, right = x + size;
    const top = y - size, bottom = y + size;

    return walls.some(w => {
        const wx1 = w.c * CELL_SIZE, wy1 = w.r * CELL_SIZE;
        const wx2 = wx1 + CELL_SIZE, wy2 = wy1 + CELL_SIZE;
        return right > wx1 && left < wx2 && bottom > wy1 && top < wy2;
    });
}

function eatDots() {
    const chompSound = document.getElementById("chomp-sound");

    dots = dots.filter(d => {
        const dx = d.c * CELL_SIZE + CELL_SIZE / 2;
        const dy = d.r * CELL_SIZE + CELL_SIZE / 2;

        if (Math.abs(pacman.x - dx) < pacman.size && Math.abs(pacman.y - dy) < pacman.size) {
            score++;
            if (chompSound) {
                chompSound.currentTime = 0;
                chompSound.volume = 0.4;
                chompSound.play();
            }
            return false;
        }
        return true;
    });

    ctx.fillStyle = "white";
    dots.forEach(d => {
        ctx.beginPath();
        ctx.arc(d.c * CELL_SIZE + CELL_SIZE / 2, d.r * CELL_SIZE + CELL_SIZE / 2, DOT_SIZE, 0, Math.PI * 2);
        ctx.fill();
    });
}

// ===== Global Functions =====
window.resetGame = resetGame;
window.exitGame = exitGame;
