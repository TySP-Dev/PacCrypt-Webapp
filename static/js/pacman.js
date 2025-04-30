// pacman.js

export function setupGame() {
    console.log('[PacMan] Game module loaded.');

    window.startPacman = startPacman;
    window.exitGame = exitGame;
}

// ====== Game Constants & State ======
let canvas, ctx, pacman, enemy, walls, dots, score;
let pacmanSpeed = 40,
    enemySpeed = 20,
    cellSize = 40,
    dotSize = 5,
    cols, rows, randSeed, gameInterval;

// ====== Game Initialization ======

export function startPacman() {
    canvas = document.getElementById("pacmanCanvas");
    ctx = canvas.getContext("2d");

    cols = Math.floor(canvas.width / cellSize);
    rows = Math.floor(canvas.height / cellSize);
    walls = [];
    dots = [];
    score = 0;

    clearInterval(gameInterval);
    const seedSource = document.getElementById("password")?.value || "pacman";
    randSeed = [...seedSource].reduce((s, c) => s + c.charCodeAt(0), 0);


    generateWalls();
    generateDots();

    pacman = spawn();
    do { enemy = spawn(); } while (enemy.x === pacman.x && enemy.y === pacman.y);

    pacman.dx = pacman.dy = 0;
    document.addEventListener("keydown", movePacman);

    gameInterval = setInterval(gameLoop, 150);
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

// ====== Game Setup Helpers ======

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
        x: s.c * cellSize + cellSize / 2,
        y: s.r * cellSize + cellSize / 2,
        size: cellSize / 2 - 5,
        dx: 0,
        dy: 0
    };
}

function rand() {
    const x = Math.sin(randSeed++) * 10000;
    return x - Math.floor(x);
}

function generateWalls() {
    for (let c = 0; c < cols; c++) {
        for (let r = 0; r < rows; r++) {
            if (c === 0 || r === 0 || c === cols - 1 || r === rows - 1 || rand() < 0.2) {
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

// ====== Game Loop & Drawing ======

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
        ctx.fillRect(w.c * cellSize, w.r * cellSize, cellSize, cellSize);
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
    ctx.fillText("Score: " + score, 10, 25);
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

// ====== Movement Logic ======

function movePacman(e) {
    const k = e.key;
    if (!["ArrowUp", "ArrowDown", "ArrowLeft", "ArrowRight"].includes(k)) return;
    e.preventDefault();

    if (k === "ArrowUp") { pacman.dx = 0; pacman.dy = -pacmanSpeed; }
    if (k === "ArrowDown") { pacman.dx = 0; pacman.dy = pacmanSpeed; }
    if (k === "ArrowLeft") { pacman.dx = -pacmanSpeed; pacman.dy = 0; }
    if (k === "ArrowRight") { pacman.dx = pacmanSpeed; pacman.dy = 0; }
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
    const moves = [[enemySpeed, 0], [-enemySpeed, 0], [0, enemySpeed], [0, -enemySpeed]];

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
        const wx1 = w.c * cellSize, wy1 = w.r * cellSize;
        const wx2 = wx1 + cellSize, wy2 = wy1 + cellSize;
        return right > wx1 && left < wx2 && bottom > wy1 && top < wy2;
    });
}

function eatDots() {
    const chompSound = document.getElementById("chomp-sound");

    dots = dots.filter(d => {
        const dx = d.c * cellSize + cellSize / 2;
        const dy = d.r * cellSize + cellSize / 2;

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
        ctx.arc(d.c * cellSize + cellSize / 2, d.r * cellSize + cellSize / 2, dotSize, 0, Math.PI * 2);
        ctx.fill();
    });
}

window.resetGame = resetGame;
window.exitGame = exitGame;
