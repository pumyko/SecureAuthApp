// templates/behavior.js
// Example JS for client-side behavioral collection
let mouseMoves = [];
let keyTimings = [];

document.addEventListener('mousemove', (e) => {
  mouseMoves.push({x: e.clientX, y: e.clientY, t: Date.now()});
  if (mouseMoves.length > 100) mouseMoves.shift();
});

document.addEventListener('keydown', (e) => {
  keyTimings.push({key: e.key, t: Date.now()});
  if (keyTimings.length > 50) keyTimings.shift();
});

function computeBehaviorScore() {
  // Simple entropy calculation example
  let mouseEntropy = mouseMoves.reduce((acc, m) => acc + Math.abs(m.x + m.y), 0) / mouseMoves.length || 0;
  let keyEntropy = keyTimings.reduce((acc, k) => acc + k.t, 0) / keyTimings.length || 0;
  return (mouseEntropy + keyEntropy) / 2 > 100 ? 0.8 : 0.4; // Threshold example
}

// When sending login, add header
// fetch('/login', { method: 'POST', headers: {'X-Behavior-Score': computeBehaviorScore()}, body: JSON.stringify(data) })