// ===== AES Encryption =====
async function encryptAdvanced(message, password) {
  // Create a random salt for key derivation
  const salt = crypto.getRandomValues(new Uint8Array(16));

  // Derive a key from the password using PBKDF2 and the salt
  const key = await deriveKey(password, salt);

  // Create a random initialization vector (IV)
  const iv = crypto.getRandomValues(new Uint8Array(12));

  // Encode the message as a Uint8Array
  const encoder = new TextEncoder();
  const encodedMessage = encoder.encode(message);

  // Encrypt the message using AES-GCM
  const encryptedMessage = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encodedMessage
  );

  // Combine salt, IV, and encrypted message
  const encryptedArray = new Uint8Array(salt.length + iv.length + encryptedMessage.byteLength);
  encryptedArray.set(salt);
  encryptedArray.set(iv, salt.length);
  encryptedArray.set(new Uint8Array(encryptedMessage), salt.length + iv.length);

  // Convert the result to base64 to send to the server
  return btoa(String.fromCharCode.apply(null, encryptedArray));
}

// Derive a key from the password using PBKDF2
async function deriveKey(password, salt) {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);

  const key = await crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    key,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ===== AES Decryption =====
async function decryptAdvanced(encryptedData, password) {
  // Decode the base64-encoded encrypted data
  const encryptedArray = new Uint8Array(atob(encryptedData).split("").map(char => char.charCodeAt(0)));

  // Extract salt, IV, and encrypted message from the encrypted data
  const salt = encryptedArray.slice(0, 16);
  const iv = encryptedArray.slice(16, 28);
  const encryptedMessage = encryptedArray.slice(28);

  // Derive the key from the password and salt
  const key = await deriveKey(password, salt);

  // Decrypt the message using AES-GCM
  const decryptedMessage = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv },
    key,
    encryptedMessage
  );

  // Decode the decrypted message to text
  const decoder = new TextDecoder();
  return decoder.decode(decryptedMessage);
}

// ===== UI Toggles =====
function toggleEncryptionOptions() {
  const type = document.getElementById("encryption-type").value;
  const pwdContainer = document.getElementById("password-input");
  pwdContainer.style.display = (type === 'advanced') ? 'flex' : 'none';
  if (type === 'basic') removeFile();
  toggleInputMode();
  document.getElementById("encrypt-label").textContent =
    (type === 'basic') ? "Encode" : "Encrypt";
  document.getElementById("decrypt-label").textContent =
    (type === 'basic') ? "Decode" : "Decrypt";
}

// ===== Remove File Button =====
function removeFile() {
  document.getElementById("file-input").value = ""; // Clear the file input
  document.getElementById("remove-file-btn").style.display = 'none'; // Hide the remove file button
  toggleInputMode(); // Reapply the input mode logic
  document.getElementById("file-password-input").style.display = 'none'; // Hide the file password input
}

// ===== Input vs. File Toggle =====
function toggleInputMode() {
  const textValue = document.getElementById("input-text").value.trim();
  const fileSelected = document.getElementById("file-input").files.length > 0;
  const isAdvanced = document.getElementById("encryption-type").value === 'advanced';

  // Show/hide text area based on file selection
  document.getElementById("text-section").style.display =
    fileSelected ? 'none' : 'flex';

  // Show/hide file input section when in advanced mode and no text input is given
  document.getElementById("file-section").style.display =
    (isAdvanced && !textValue) ? 'flex' : 'none';

  // Show/hide the remove file button
  document.getElementById("remove-file-btn").style.display =
    fileSelected ? 'inline-block' : 'none';

  // ALWAYS show the password input in advanced mode
  if (isAdvanced) {
    document.getElementById("password-input").style.display = 'flex';
  } else {
    document.getElementById("password-input").style.display = 'none';
  }

  // Show the dedicated password input for file encryption if a file is selected
  if (fileSelected) {
    document.getElementById("file-password-input").style.display = 'flex';  // Show password input for files
  } else {
    document.getElementById("file-password-input").style.display = 'none';  // Hide when no file is selected
  }
}

// ===== Validate and Submit Form =====
async function handleSubmit(event) {
  event.preventDefault();

  // If the encryption type is advanced, ensure password is provided
  const password = document.getElementById("password").value;
  const filePassword = document.getElementById("file-password") ? document.getElementById("file-password").value : '';
  const encryptionType = document.getElementById("encryption-type").value;

  if (encryptionType === 'advanced' && !password && !filePassword) {
    alert("Password is required for advanced encryption.");
    return;
  }

  // Prepare the form data
  const payload = {
    "encryption-type": encryptionType,
    operation: document.querySelector('input[name="operation"]:checked').value,
    message: document.getElementById("input-text").value,
    password: password,
    "file-password": filePassword
  };

  // Handle file upload encryption/decryption
  const fileInput = document.getElementById("file-input");
  if (fileInput.files.length > 0) {
    const op = document.querySelector('input[name="operation"]:checked').value;
    if (op === 'encrypt') encryptFile();
    else decryptFile();
    return;
  }

  // Handle text encryption/decryption
  try {
    const resp = await fetch("/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await resp.json();
    document.getElementById("output-text").value = data.result;
  } catch (err) {
    alert("Error processing request: " + err);
  }
}

// ===== File Encryption / Decryption =====
function encryptFile() {
  const f = document.getElementById("file-input");
  const pwd = document.getElementById("file-password").value;
  if (!pwd) return alert("Please enter a password!");
  if (!f.files.length) return alert("Please select a file!");
  const reader = new FileReader();
  reader.onload = async (e) => {
    const raw = e.target.result;
    let encryptedMessage = await encryptAdvanced(raw, pwd);
    downloadFile(encryptedMessage, f.files[0].name + ".enc");
  };
  reader.readAsText(f.files[0]);
}

function decryptFile() {
  const f = document.getElementById("file-input");
  const pwd = document.getElementById("file-password").value;
  if (!pwd) return alert("Please enter a password!");
  if (!f.files.length) return alert("Please select a file!");
  const reader = new FileReader();
  reader.onload = async (e) => {
    try {
      const enc = e.target.result;
      const decryptedMessage = await decryptAdvanced(enc, pwd);
      downloadFile(decryptedMessage, f.files[0].name.replace(/\.enc$/, ''));
    } catch {
      alert("Decryption failed: wrong password or corrupted file.");
    }
  };
  reader.readAsText(f.files[0]);
}

function downloadFile(content, filename) {
  const blob = new Blob([content], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ===== Password Generator =====
function generateRandomPassword() {
  const length = 30;
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+[]{}|;:,.<>?/~";
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  document.getElementById("password-field").value = password;
}

// ===== Copy to Clipboard =====
function copyToClipboard(elementId, toastId) {
  const copyText = document.getElementById(elementId);
  copyText.select();
  copyText.setSelectionRange(0, 99999); // For mobile devices
  document.execCommand("copy");

  // Show toast notification
  const toast = document.getElementById(toastId);
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), 2000); // Remove toast after 2 seconds
}

// ===== Pacman Easter Egg =====
function checkForPacman() {
  const val = document.getElementById("input-text").value.trim().toLowerCase();
  const pacSection = document.getElementById("pacman-section");
  const encSection = document.getElementById("encoding-section");

  if (val.includes('pacman') && pacSection.style.display !== 'block') {
    pacSection.style.display = 'block';
    encSection.style.display = 'none';
    startPacman();
  } else if (pacSection.style.display === 'block' && !val.includes('pacman')) {
    exitGame();
  }
}

// ===== Game Exit & Restart =====
function exitGame() {
  stopPacman();
  document.getElementById("input-text").value = "";
  document.getElementById("pacman-section").style.display = 'none';
  document.getElementById("encoding-section").style.display = 'block';
}

function resetGame() {
  stopPacman();
  startPacman();
}

// ===== Pacman Game Variables & Logic =====
let canvas, ctx, pacman, enemy, walls, dots, score;
let pacmanSpeed = 40, enemySpeed = 20, cellSize = 40, dotSize = 5;
let cols, rows, randSeed, gameInterval;

function startPacman() {
  canvas = document.getElementById("pacmanCanvas");
  ctx = canvas.getContext("2d");
  cols = Math.floor(canvas.width / cellSize);
  rows = Math.floor(canvas.height / cellSize);
  walls = []; dots = []; score = 0;
  clearInterval(gameInterval);

  randSeed = Array.from(
    document.getElementById("password-field").value
  ).reduce((s, c) => s + c.charCodeAt(0), 0);

  generateWalls();
  generateDots();

  pacman = spawn();
  do {
    enemy = spawn();
  } while (enemy.x === pacman.x && enemy.y === pacman.y);

  pacman.dx = pacman.dy = 0;
  document.addEventListener("keydown", movePacman);
  gameInterval = setInterval(gameLoop, 150);
}

function stopPacman() {
  clearInterval(gameInterval);
  if (ctx) ctx.clearRect(0, 0, canvas.width, canvas.height);
}

function spawn() {
  const opts = [];
  for (let c = 1; c < cols - 1; c++) {
    for (let r = 1; r < rows - 1; r++) {
      if (!walls.some(w => w.c === c && w.r === r)) {
        const neighbors = [
          { c: c+1, r }, { c: c-1, r },
          { c, r: r+1 }, { c, r: r-1 }
        ];
        if (neighbors.some(n =>
          !walls.some(w => w.c===n.c && w.r===n.r)
        )) {
          opts.push({ c, r });
        }
      }
    }
  }
  const s = opts[Math.floor(rand() * opts.length)];
  return {
    x: s.c * cellSize + cellSize/2,
    y: s.r * cellSize + cellSize/2,
    size: cellSize/2 - 5,
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
      if (c===0||r===0||c===cols-1||r===rows-1||rand()<0.2) {
        walls.push({ c, r });
      }
    }
  }
}

function generateDots() {
  dots = [];
  for (let c = 1; c < cols - 1; c++) {
    for (let r = 1; r < rows - 1; r++) {
      if (walls.some(w => w.c===c && w.r===r)) continue;
      const isEnclosed =
        walls.some(w => w.c===c+1 && w.r===r) &&
        walls.some(w => w.c===c-1 && w.r===r) &&
        walls.some(w => w.c===c && w.r===r+1) &&
        walls.some(w => w.c===c && w.r===r-1);
      if (!isEnclosed) dots.push({ c, r });
    }
  }
}

function movePacman(e) {
  if (!["ArrowUp","ArrowDown","ArrowLeft","ArrowRight"].includes(e.key)) return;
  e.preventDefault();
  if (e.key==="ArrowUp")    { pacman.dx=0; pacman.dy=-pacmanSpeed; }
  if (e.key==="ArrowDown")  { pacman.dx=0; pacman.dy=pacmanSpeed; }
  if (e.key==="ArrowLeft")  { pacman.dx=-pacmanSpeed; pacman.dy=0; }
  if (e.key==="ArrowRight") { pacman.dx=pacmanSpeed;  pacman.dy=0; }
}

// ===== Collision Helper =====
function willCollide(x, y, size) {
  const left = x - size, right = x + size;
  const top = y - size, bottom = y + size;
  for (let w of walls) {
    const wx1 = w.c * cellSize, wy1 = w.r * cellSize;
    const wx2 = wx1 + cellSize, wy2 = wy1 + cellSize;
    if (right > wx1 && left < wx2 && bottom > wy1 && top < wy2) {
      return true;
    }
  }
  return false;
}

function moveChar(ch) {
  const nx = ch.x + ch.dx, ny = ch.y + ch.dy;
  if (!willCollide(nx, ny, ch.size)) {
    ch.x = nx; ch.y = ny;
  }
}

function moveEnemy() {
  const options = [];
  [[enemySpeed,0],[-enemySpeed,0],[0,enemySpeed],[0,-enemySpeed]].forEach(
    ([dx,dy]) => {
      const nx = enemy.x + dx, ny = enemy.y + dy;
      if (!willCollide(nx, ny, enemy.size)) options.push({dx,dy});
    }
  );
  if (!options.length) return;
  let best = options[0];
  let bestD = Math.abs(enemy.x+best.dx-pacman.x)+Math.abs(enemy.y+best.dy-pacman.y);
  for (let opt of options) {
    const d = Math.abs(enemy.x+opt.dx-pacman.x)+Math.abs(enemy.y+opt.dy-pacman.y);
    if (d < bestD) { best=opt; bestD=d; }
  }
  enemy.x += best.dx; enemy.y += best.dy;
}

function gameLoop() {
  ctx.clearRect(0,0,canvas.width,canvas.height);
  drawWalls();
  moveChar(pacman);
  moveEnemy();
  drawChar(pacman,"yellow");
  drawChar(enemy,"red");
  eatDots();
  drawScore();
  checkGameOver();
}

function drawWalls() {
  ctx.fillStyle="blue";
  walls.forEach(w=>ctx.fillRect(w.c*cellSize,w.r*cellSize,cellSize,cellSize));
}

function drawChar(ch,color) {
  ctx.beginPath();
  ctx.arc(ch.x,ch.y,ch.size,0,Math.PI*2);
  ctx.fillStyle=color; ctx.fill();
}

function eatDots() {
  dots = dots.filter(d=>{
    const dx = d.c*cellSize+cellSize/2, dy = d.r*cellSize+cellSize/2;
    if (Math.abs(pacman.x-dx)<pacman.size && Math.abs(pacman.y-dy)<pacman.size) {
      score++;
      return false;
    }
    return true;
  });
  ctx.fillStyle="white";
  dots.forEach(d=>{
    ctx.beginPath();
    ctx.arc(d.c*cellSize+cellSize/2, d.r*cellSize+cellSize/2, dotSize,0,Math.PI*2);
    ctx.fill();
  });
}

function drawScore() {
  ctx.fillStyle="white";
  ctx.font="20px Poppins";
  ctx.fillText("Score: "+score,10,25);
}

function checkGameOver() {
  if (Math.abs(pacman.x-enemy.x)<pacman.size && Math.abs(pacman.y-enemy.y)<pacman.size) {
    ctx.fillStyle="#00ff99";
    ctx.font="40px Poppins";
    ctx.textAlign="center";
    ctx.fillText("Game Over!", canvas.width/2, canvas.height/2);
    clearInterval(gameInterval);
  }
}

// ===== Clear All Functionality =====
function clearAll() {
  document.getElementById("input-text").value = "";
  document.getElementById("output-text").value = "";
  document.getElementById("file-input").value = "";
  document.getElementById("password").value = "";
  document.getElementById("file-password").value = "";

  document.getElementById("pacman-section").style.display = "none";
  document.getElementById("encoding-section").style.display = "block";

  removeFile();
  toggleInputMode();
}

// ===== Initialize =====
document.addEventListener("DOMContentLoaded", () => {
  toggleEncryptionOptions();
  toggleInputMode();
  document.getElementById("input-text").addEventListener("input", checkForPacman);
});
