import {
    Scene, PerspectiveCamera, WebGLRenderer,
    Color, Vector2, Vector3, Clock, Raycaster, Plane,
    Group, Mesh, Line, Points,
    BufferGeometry, BufferAttribute,
    SphereGeometry, PlaneGeometry, RingGeometry,
    MeshBasicMaterial, LineBasicMaterial, PointsMaterial, ShaderMaterial,
    DoubleSide,
} from 'three';

const isMobile = window.innerWidth < 968;
const COLS = isMobile ? 8 : 12, ROWS = isMobile ? 5 : 8, SPACING = 8;
const GREEN = new Color(0x00ff41), AMBER = new Color(0xff9500), RED = new Color(0xff3333);

// Scene setup
const scene = new Scene();
const camera = new PerspectiveCamera(50, innerWidth / innerHeight, 0.1, 300);
camera.position.set(0, 0, 80);
const renderer = new WebGLRenderer({ antialias: !isMobile, alpha: true });
renderer.setSize(innerWidth, innerHeight);
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
renderer.setClearColor(0x0c0c0c);
document.getElementById('canvas-container').appendChild(renderer.domElement);

// Bloom (desktop only, dynamically imported to reduce mobile bundle)
let composer = null;
if (!isMobile) {
    const [{ EffectComposer }, { RenderPass }, { UnrealBloomPass }] = await Promise.all([
        import('three/examples/jsm/postprocessing/EffectComposer.js'),
        import('three/examples/jsm/postprocessing/RenderPass.js'),
        import('three/examples/jsm/postprocessing/UnrealBloomPass.js'),
    ]);
    composer = new EffectComposer(renderer);
    composer.addPass(new RenderPass(scene, camera));
    const bloom = new UnrealBloomPass(new Vector2(innerWidth, innerHeight), 0.6, 0.4, 0.85);
    composer.addPass(bloom);
}

// === Background stars (depth parallax layer) ===
const starCount = 150;
const starPos = new Float32Array(starCount * 3);
for (let i = 0; i < starCount; i++) {
    starPos[i * 3] = (Math.random() - 0.5) * 200;
    starPos[i * 3 + 1] = (Math.random() - 0.5) * 120;
    starPos[i * 3 + 2] = -25 - Math.random() * 25;
}
const starGeo = new BufferGeometry();
starGeo.setAttribute('position', new BufferAttribute(starPos, 3));
const starMat = new PointsMaterial({
    color: 0x00ff41, size: 0.6, transparent: true, opacity: 0.2, sizeAttenuation: true,
});
const stars = new Points(starGeo, starMat);
scene.add(stars);

// Grid nodes
const nodes = [], edges = [], gridMap = new Map();
const gridGroup = new Group();
scene.add(gridGroup);
const offsetX = (COLS - 1) * SPACING / 2, offsetY = (ROWS - 1) * SPACING / 2;

const nodeMat = new MeshBasicMaterial({ color: GREEN });
const nodeGeo = new SphereGeometry(0.3, 8, 8);
const hubGeo = new SphereGeometry(0.5, 12, 12);

for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
        const isHub = (r % 3 === 0 && c % 3 === 0);
        const mesh = new Mesh(isHub ? hubGeo : nodeGeo, nodeMat.clone());
        const ox = (Math.random() - 0.5) * 2, oy = (Math.random() - 0.5) * 2;
        mesh.position.set(c * SPACING - offsetX + ox, r * SPACING - offsetY + oy, 0);
        mesh.userData = { col: c, row: r, isHub, basePos: mesh.position.clone(), baseColor: GREEN.clone(), isThreat: false };
        gridGroup.add(mesh);
        nodes.push(mesh);
        gridMap.set(`${c},${r}`, mesh);
    }
}

// Edges
const edgeLineMat = new LineBasicMaterial({ color: GREEN, transparent: true, opacity: 0.1 });
const dirs = [[1, 0], [0, 1], [1, 1], [-1, 1]];
for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
        const n = gridMap.get(`${c},${r}`);
        for (const [dc, dr] of dirs) {
            const nb = gridMap.get(`${c + dc},${r + dr}`);
            if (!nb) continue;
            const geo = new BufferGeometry().setFromPoints([n.position, nb.position]);
            const line = new Line(geo, edgeLineMat.clone());
            gridGroup.add(line);
            edges.push({ line, from: n, to: nb });
        }
    }
}

// Scan line (subtler: opacity 0.25, 14s period)
const scanGeo = new PlaneGeometry(COLS * SPACING + 20, 0.15);
const scanMat = new MeshBasicMaterial({ color: GREEN, transparent: true, opacity: 0.25 });
const scanLine = new Mesh(scanGeo, scanMat);
scanLine.position.z = 0.5;
gridGroup.add(scanLine);

// Scan trail (subtler: trail opacity 0.06)
const trailGeo = new PlaneGeometry(COLS * SPACING + 20, 4);
const trailMat = new ShaderMaterial({
    transparent: true, depthWrite: false,
    uniforms: { color: { value: GREEN } },
    vertexShader: `varying vec2 vUv; void main(){vUv=uv;gl_Position=projectionMatrix*modelViewMatrix*vec4(position,1.0);}`,
    fragmentShader: `uniform vec3 color;varying vec2 vUv;void main(){float a=smoothstep(0.0,1.0,vUv.y)*0.06;gl_FragColor=vec4(color,a);}`,
});
const scanTrail = new Mesh(trailGeo, trailMat);
scanTrail.position.z = 0.3;
gridGroup.add(scanTrail);

// Data packets
const packets = [];
const packetGeo = new PlaneGeometry(0.35, 0.35);
function spawnPacket() {
    const startNode = nodes[Math.floor(Math.random() * nodes.length)];
    const type = Math.random();
    const color = type < 0.05 ? RED : type < 0.2 ? AMBER : GREEN;
    const speed = color === AMBER ? 0.08 : color === RED ? 0.04 : 0.05;
    const mat = new MeshBasicMaterial({ color, transparent: true, opacity: 0.9 });
    const mesh = new Mesh(packetGeo, mat);
    mesh.position.copy(startNode.position);
    mesh.position.z = 1;
    gridGroup.add(mesh);
    packets.push({ mesh, current: startNode, target: null, progress: 0, speed, color, age: 0 });
}
for (let i = 0; i < (isMobile ? 12 : 25); i++) spawnPacket();

function getNeighbor(node) {
    const { col, row } = node.userData;
    const cardinalDirs = [[1, 0], [-1, 0], [0, 1], [0, -1]];
    const shuffled = cardinalDirs.sort(() => Math.random() - 0.5);
    for (const [dc, dr] of shuffled) {
        const nb = gridMap.get(`${col + dc},${row + dr}`);
        if (nb) return nb;
    }
    return null;
}

// Mouse interaction
const mouse = new Vector2(9999, 9999);
const mouseWorld = new Vector3();
const raycaster = new Raycaster();
const intersectPlane = new Plane(new Vector3(0, 0, 1), 0);

window.addEventListener('mousemove', e => {
    mouse.x = (e.clientX / innerWidth) * 2 - 1;
    mouse.y = -(e.clientY / innerHeight) * 2 + 1;
    raycaster.setFromCamera(mouse, camera);
    raycaster.ray.intersectPlane(intersectPlane, mouseWorld);
}, { passive: true });

// Touch support
window.addEventListener('touchmove', e => {
    const touch = e.touches[0];
    mouse.x = (touch.clientX / innerWidth) * 2 - 1;
    mouse.y = -(touch.clientY / innerHeight) * 2 + 1;
    raycaster.setFromCamera(mouse, camera);
    raycaster.ray.intersectPlane(intersectPlane, mouseWorld);
}, { passive: true });

window.addEventListener('touchend', e => {
    if (e.changedTouches.length) {
        const touch = e.changedTouches[0];
        mouse.x = (touch.clientX / innerWidth) * 2 - 1;
        mouse.y = -(touch.clientY / innerHeight) * 2 + 1;
        raycaster.setFromCamera(mouse, camera);
        raycaster.ray.intersectPlane(intersectPlane, mouseWorld);
        // Trigger tap pulse
        const ringGeo = new RingGeometry(0.5, 1, 32);
        const ringMat = new MeshBasicMaterial({ color: GREEN, transparent: true, opacity: 0.6, side: DoubleSide });
        const ring = new Mesh(ringGeo, ringMat);
        ring.position.set(mouseWorld.x, mouseWorld.y, 1);
        gridGroup.add(ring);
        pulses.push({ mesh: ring, radius: 1, age: 0 });
    }
}, { passive: true });

// Click pulse
const pulses = [];
window.addEventListener('click', () => {
    if (mouseWorld.x === 0 && mouseWorld.y === 0) return;
    const ringGeo = new RingGeometry(0.5, 1, 32);
    const ringMat = new MeshBasicMaterial({ color: GREEN, transparent: true, opacity: 0.6, side: DoubleSide });
    const ring = new Mesh(ringGeo, ringMat);
    ring.position.set(mouseWorld.x, mouseWorld.y, 1);
    gridGroup.add(ring);
    pulses.push({ mesh: ring, radius: 1, age: 0 });
});

// Threat events
let threatTimer = 0;
const activeThreats = [];

// Smooth scroll with lerp - cached scrollHeight, rAF-synced reads
let scrollTarget = 0;
let smoothScroll = 0;
let cachedScrollMax = Math.max(1, document.body.scrollHeight - innerHeight);
let scrollDirty = false;

// Recalculate once after fonts and images load
window.addEventListener('load', () => {
    cachedScrollMax = Math.max(1, document.body.scrollHeight - innerHeight);
});

window.addEventListener('scroll', () => {
    scrollDirty = true;
}, { passive: true });

// Resize
window.addEventListener('resize', () => {
    camera.aspect = innerWidth / innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(innerWidth, innerHeight);
    if (composer) composer.setSize(innerWidth, innerHeight);
    cachedScrollMax = Math.max(1, document.body.scrollHeight - innerHeight);
});

// Pre-allocated reusable objects to avoid GC in animation loop
const _white = new Color(1, 1, 1);
const _tmpColor = new Color();
const _midVec = new Vector3();

// Animation
const clock = new Clock();
function animate() {
    requestAnimationFrame(animate);
    const dt = Math.min(clock.getDelta(), 0.05);
    const t = clock.getElapsedTime();

    // Read scroll position inside rAF to avoid layout thrashing
    if (scrollDirty) {
        scrollTarget = Math.min(window.scrollY / cachedScrollMax, 1);
        scrollDirty = false;
    }
    // Faster lerp (0.12) for responsive scroll tracking without lag
    smoothScroll += (scrollTarget - smoothScroll) * 0.12;

    // Scan line sweep (14s period, subtler)
    const scanY = -offsetY + ((t % 14) / 14) * (ROWS - 1) * SPACING;
    scanLine.position.y = scanY;
    scanTrail.position.y = scanY - 2;

    // Node flash from scan line (reduced to 0.2 intensity)
    for (const node of nodes) {
        const dist = Math.abs(node.position.y - scanY);
        const flash = dist < 2 ? (1 - dist / 2) * 0.2 : 0;
        if (!node.userData.isThreat) {
            _tmpColor.copy(node.userData.baseColor);
            _tmpColor.lerp(_white, flash);
            node.material.color.copy(_tmpColor);
        }
    }

    // Mouse interaction: magnetic pull + highlight
    for (const node of nodes) {
        const dx = mouseWorld.x - node.userData.basePos.x;
        const dy = mouseWorld.y - node.userData.basePos.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 15) {
            const pull = (1 - dist / 15) * 2;
            node.position.x = node.userData.basePos.x + dx * pull * 0.05;
            node.position.y = node.userData.basePos.y + dy * pull * 0.05;
        } else {
            node.position.x += (node.userData.basePos.x - node.position.x) * 0.05;
            node.position.y += (node.userData.basePos.y - node.position.y) * 0.05;
        }
    }

    // Highlight edges near cursor
    for (const edge of edges) {
        _midVec.addVectors(edge.from.position, edge.to.position).multiplyScalar(0.5);
        const dx = mouseWorld.x - _midVec.x, dy = mouseWorld.y - _midVec.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        edge.line.material.opacity = dist < 12 ? 0.1 + (1 - dist / 12) * 0.15 : 0.1;
    }

    // Packets
    for (const p of packets) {
        p.age += dt;
        if (!p.target) {
            p.target = getNeighbor(p.current);
            p.progress = 0;
            if (!p.target) { p.target = nodes[Math.floor(Math.random() * nodes.length)]; }
        }
        p.progress += p.speed;
        if (p.progress >= 1) {
            p.current = p.target;
            p.target = null;
            p.progress = 0;
            p.mesh.position.copy(p.current.position);
            p.mesh.position.z = 1;
        } else {
            p.mesh.position.lerpVectors(p.current.position, p.target.position, p.progress);
            p.mesh.position.z = 1;
        }
        if (p.color === RED) {
            p.mesh.material.opacity = 0.6 + Math.sin(t * 6) * 0.4;
        }
        if (p.age > 30) {
            p.age = 0;
            p.current = nodes[Math.floor(Math.random() * nodes.length)];
            p.target = null;
            p.mesh.position.copy(p.current.position);
        }
    }

    // Click pulses
    for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i];
        p.age += dt;
        p.radius += dt * 25;
        p.mesh.scale.set(p.radius, p.radius, 1);
        p.mesh.material.opacity = Math.max(0, 0.6 - p.age * 0.8);
        if (p.age > 1) {
            gridGroup.remove(p.mesh);
            p.mesh.geometry.dispose();
            p.mesh.material.dispose();
            pulses.splice(i, 1);
        }
    }

    // Threat events
    threatTimer += dt;
    if (threatTimer > 5 && activeThreats.length < 4) {
        threatTimer = 0;
        const idx = Math.floor(Math.random() * nodes.length);
        const node = nodes[idx];
        if (!node.userData.isThreat) {
            node.userData.isThreat = true;
            node.material.color.copy(RED);
            activeThreats.push({ node, age: 0 });
        }
    }
    for (let i = activeThreats.length - 1; i >= 0; i--) {
        const th = activeThreats[i];
        th.age += dt;
        const pulse = Math.sin(th.age * 8) * 0.3 + 0.7;
        th.node.scale.setScalar(pulse * (th.node.userData.isHub ? 1.4 : 1));
        if (th.age > 2.5) {
            th.node.userData.isThreat = false;
            th.node.material.color.copy(th.node.userData.baseColor);
            th.node.scale.setScalar(1);
            activeThreats.splice(i, 1);
        }
    }

    // Scroll perspective
    gridGroup.rotation.x = smoothScroll * 0.12;

    // Star parallax
    stars.position.x = mouseWorld.x * 0.008;
    stars.position.y = mouseWorld.y * 0.008 - smoothScroll * 3;

    if (composer) composer.render();
    else renderer.render(scene, camera);
}
animate();
