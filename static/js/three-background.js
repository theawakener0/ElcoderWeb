import * as THREE from 'https://unpkg.com/three@0.157.0/build/three.module.js';

class ParticleBackground {
    constructor() {
        this.scene = new THREE.Scene();
        this.camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        this.renderer = new THREE.WebGLRenderer({
            canvas: document.querySelector('#bg-canvas'),
            alpha: true,
            antialias: true
        });
        this.renderer.domElement.style.position = 'fixed';
        this.renderer.domElement.style.top = '0';
        this.renderer.domElement.style.left = '0';
        this.renderer.domElement.style.zIndex = '1';
        this.renderer.domElement.style.pointerEvents = 'none';
        this.particles = [];
        this.mouseX = 0;
        this.mouseY = 0;
        this.scrollY = 0;
        this.targetScrollY = 0;
        this.clock = new THREE.Clock();
        this.colorIndex = 0;
        this.targetColorIndex = 0;
        this.colors = [0x800080, 0x9400D3, 0x8A2BE2, 0x9370DB];

        this.init();
    }

    init() {
        this.renderer.setPixelRatio(window.devicePixelRatio);
        this.renderer.setSize(window.innerWidth, window.innerHeight);
        this.camera.position.setZ(30);

        this.createParticles();
        this.setupLighting();
        this.setupEventListeners();
        this.animate();
    }

    setupLighting() {
        const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
        this.scene.add(ambientLight);

        const colors = [0x800080, 0x9400D3, 0x8A2BE2, 0x9370DB, 0xBA55D3, 0xDDA0DD];
        for (let i = 0; i < 6; i++) {
            const color = colors[i];
            const pointLight = new THREE.PointLight(color, 2.0, 50);
            pointLight.position.set(
                (Math.random() - 0.5) * 40,
                (Math.random() - 0.5) * 40,
                (Math.random() - 0.5) * 40
            );
            this.scene.add(pointLight);
        }
    }

    createParticles() {
        const particlesGeometry = new THREE.BufferGeometry();
        const particlesCnt = 5000;
        const posArray = new Float32Array(particlesCnt * 3);
        const colorsArray = new Float32Array(particlesCnt * 3);
        const sizesArray = new Float32Array(particlesCnt);

        const colors = [new THREE.Color(0x800080), new THREE.Color(0x9400D3), 
                        new THREE.Color(0x8A2BE2), new THREE.Color(0x9370DB)];

        for(let i = 0; i < particlesCnt * 3; i += 3) {
            posArray[i] = (Math.random() - 0.5) * 100;
            posArray[i + 1] = (Math.random() - 0.5) * 100;
            posArray[i + 2] = (Math.random() - 0.5) * 100;

            const color = colors[Math.floor(Math.random() * colors.length)];
            colorsArray[i] = color.r;
            colorsArray[i + 1] = color.g;
            colorsArray[i + 2] = color.b;

            sizesArray[i/3] = Math.random() * 0.5 + 0.1;
        }

        particlesGeometry.setAttribute('position', new THREE.BufferAttribute(posArray, 3));
        particlesGeometry.setAttribute('color', new THREE.BufferAttribute(colorsArray, 3));
        particlesGeometry.setAttribute('size', new THREE.BufferAttribute(sizesArray, 1));

        const particlesMaterial = new THREE.ShaderMaterial({
            uniforms: {
                time: { value: 0 },
                mouseX: { value: 0 },
                mouseY: { value: 0 },
                scroll: { value: 0 },
                colorIndex: { value: 0 }
            },
            vertexShader: `
                attribute float size;
                attribute vec3 color;
                varying vec3 vColor;
                uniform float time;
                uniform float mouseX;
                uniform float mouseY;
                uniform float scroll;
                uniform float colorIndex;

                void main() {
                    vColor = color;
                    vec3 pos = position;
                    pos.x += sin(time * 0.3 + position.y * 0.05) * 0.5;
                    pos.y += cos(time * 0.3 + position.x * 0.05) * 0.5;
                    pos.x += mouseX * 10.0;
                    pos.y += mouseY * 10.0;
                    pos.z += scroll * 20.0;
                    vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
                    gl_PointSize = size * (300.0 / -mvPosition.z);
                    gl_Position = projectionMatrix * mvPosition;
                }
            `,
            fragmentShader: `
                varying vec3 vColor;

                void main() {
                    float dist = length(gl_PointCoord - vec2(0.5));
                    if (dist > 0.5) discard;
                    gl_FragColor = vec4(vColor, 1.0 - (dist * 2.0));
                }
            `,
            transparent: true,
            blending: THREE.AdditiveBlending,
            depthWrite: false
        });

        const particlesMesh = new THREE.Points(particlesGeometry, particlesMaterial);
        this.scene.add(particlesMesh);
        this.particles.push(particlesMesh);
    }

    setupEventListeners() {
        window.addEventListener('resize', () => {
            this.camera.aspect = window.innerWidth / window.innerHeight;
            this.camera.updateProjectionMatrix();
            this.renderer.setSize(window.innerWidth, window.innerHeight);
        });

        document.addEventListener('mousemove', (event) => {
            this.mouseX = (event.clientX / window.innerWidth - 0.5) * 2;
            this.mouseY = (event.clientY / window.innerHeight - 0.5) * -2;
        });

        window.addEventListener('scroll', () => {
            this.targetScrollY = window.scrollY / (document.documentElement.scrollHeight - window.innerHeight);
            this.targetColorIndex = Math.floor(this.targetScrollY * this.colors.length);
        });
    }

    animate() {
        requestAnimationFrame(this.animate.bind(this));
        const elapsedTime = this.clock.getElapsedTime();

        // Smooth scroll and color transitions
        this.scrollY += (this.targetScrollY - this.scrollY) * 0.1;
        this.colorIndex += (this.targetColorIndex - this.colorIndex) * 0.05;

        this.particles.forEach(particle => {
            particle.material.uniforms.time.value = elapsedTime;
            particle.material.uniforms.mouseX.value = this.mouseX;
            particle.material.uniforms.mouseY.value = this.mouseY;
            particle.material.uniforms.scroll.value = this.scrollY;
            particle.material.uniforms.colorIndex.value = this.colorIndex;
            particle.rotation.x += 0.0001;
            particle.rotation.y += 0.0001;
        });

        this.renderer.render(this.scene, this.camera);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.createElement('canvas');
    canvas.id = 'bg-canvas';
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.zIndex = '-1';
    canvas.style.pointerEvents = 'none';
    document.body.prepend(canvas);

    new ParticleBackground();
});