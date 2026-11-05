/* ═══════════════════════════════════════════════════════════
   CreativePort — Cinematic Engine (Vanilla JS)
   Replicates: CinematicIntro, Hero3D ParticleWave,
   CursorGlow, MagneticButton, GlassCard, SectionWrapper
   ═══════════════════════════════════════════════════════════ */

(function() {
    'use strict';



    // ─── PARTICLE WAVE (Canvas) ────────────────────────────
    const canvas = document.getElementById('particle-canvas');
    if (canvas) {
        const ctx = canvas.getContext('2d');
        let W, H, particles = [], mouseX = 0, mouseY = 0;

        function resize() {
            W = canvas.width = window.innerWidth;
            H = canvas.height = window.innerHeight;
        }
        resize();
        window.addEventListener('resize', resize);
        window.addEventListener('mousemove', e => { mouseX = e.clientX; mouseY = e.clientY; });

        // Create particles
        for (let i = 0; i < 120; i++) {
            particles.push({
                x: Math.random() * W,
                y: Math.random() * H,
                size: Math.random() * 2 + 0.5,
                speedX: (Math.random() - 0.5) * 0.6,
                speedY: (Math.random() - 0.5) * 0.6,
                opacity: Math.random() * 0.5 + 0.1,
                hue: Math.random() > 0.5 ? 45 : 38
            });
        }

        function drawParticles() {
            ctx.clearRect(0, 0, W, H);
            
            for (const p of particles) {
                p.x += p.speedX;
                p.y += p.speedY;
                if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
                if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;

                // Mouse repulsion
                const dx = p.x - mouseX, dy = p.y - mouseY;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 150) {
                    const force = (150 - dist) / 150;
                    p.x += (dx / dist) * force * 2;
                    p.y += (dy / dist) * force * 2;
                }

                ctx.beginPath();
                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                ctx.fillStyle = `hsla(${p.hue},100%,70%,${p.opacity})`;
                ctx.fill();
            }

            // Connect nearby particles
            for (let i = 0; i < particles.length; i++) {
                for (let j = i + 1; j < particles.length; j++) {
                    const dx = particles[i].x - particles[j].x;
                    const dy = particles[i].y - particles[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < 100) {
                        ctx.beginPath();
                        ctx.moveTo(particles[i].x, particles[i].y);
                        ctx.lineTo(particles[j].x, particles[j].y);
                        ctx.strokeStyle = `rgba(255,215,0,${0.06 * (1 - dist / 100)})`;
                        ctx.lineWidth = 0.5;
                        ctx.stroke();
                    }
                }
            }
            requestAnimationFrame(drawParticles);
        }
        drawParticles();
    }

    // ─── CUSTOM CURSOR (3-layer: dot + ring + glow) ────────
    const dot = document.getElementById('cursorDot');
    const ring = document.getElementById('cursorRing');
    const glow = document.getElementById('cursorGlow');
    const cursorText = document.getElementById('cursorText');

    if (dot && ring && glow) {
        let dotX = 0, dotY = 0, ringX = 0, ringY = 0, glowX = 0, glowY = 0;
        let targetX = 0, targetY = 0;

        window.addEventListener('mousemove', e => {
            targetX = e.clientX; targetY = e.clientY;
        });

        function animateCursor() {
            // Dot: instant
            dotX += (targetX - dotX) * 0.9;
            dotY += (targetY - dotY) * 0.9;
            dot.style.left = dotX + 'px';
            dot.style.top = dotY + 'px';

            // Ring: trailing
            ringX += (targetX - ringX) * 0.15;
            ringY += (targetY - ringY) * 0.15;
            ring.style.left = ringX + 'px';
            ring.style.top = ringY + 'px';

            // Glow: heavy trail
            glowX += (targetX - glowX) * 0.05;
            glowY += (targetY - glowY) * 0.05;
            glow.style.left = glowX + 'px';
            glow.style.top = glowY + 'px';

            if (cursorText) {
                cursorText.style.left = ringX + 'px';
                cursorText.style.top = (ringY + 40) + 'px';
            }

            requestAnimationFrame(animateCursor);
        }
        animateCursor();

        // Hover detection
        document.addEventListener('mouseover', e => {
            const target = e.target.closest('a, button, [data-cursor], .interactable, .skill-pill, .project-card');
            if (target) {
                document.body.classList.add('hovered');
                if (cursorText && target.dataset.cursor) {
                    cursorText.textContent = target.dataset.cursor;
                }
            }
        });
        document.addEventListener('mouseout', e => {
            const target = e.target.closest('a, button, [data-cursor], .interactable, .skill-pill, .project-card');
            if (target) {
                document.body.classList.remove('hovered');
                if (cursorText) cursorText.textContent = '';
            }
        });
    }

    // ─── MAGNETIC BUTTONS ──────────────────────────────────
    document.querySelectorAll('.magnetic-wrap').forEach(wrap => {
        const btn = wrap.querySelector('.btn-cta');
        if (!btn) return;
        
        wrap.addEventListener('mousemove', e => {
            const rect = wrap.getBoundingClientRect();
            const x = e.clientX - rect.left - rect.width / 2;
            const y = e.clientY - rect.top - rect.height / 2;
            gsap.to(btn, { x: x * 0.4, y: y * 0.4, duration: 0.3, ease: 'power2.out' });
        });
        wrap.addEventListener('mouseleave', () => {
            gsap.to(btn, { x: 0, y: 0, duration: 0.7, ease: 'elastic.out(1,0.3)' });
        });
    });

    // ─── GLASS CARD 3D TILT (replaces GlassCard.jsx) ──────
    document.querySelectorAll('.tilt-card').forEach(card => {
        const glowEl = card.querySelector('.card-glow');

        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            const x = (e.clientX - rect.left) / rect.width;
            const y = (e.clientY - rect.top) / rect.height;
            const rotateX = (y - 0.5) * -16;
            const rotateY = (x - 0.5) * 16;
            
            card.style.transform = `perspective(800px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) scale3d(1.03,1.03,1.03)`;
            
            if (glowEl) {
                glowEl.style.background = `radial-gradient(circle at ${x*100}% ${y*100}%, rgba(255,215,0,0.12) 0%, rgba(197,160,0,0.05) 40%, transparent 70%)`;
            }
        });
        card.addEventListener('mouseleave', () => {
            card.style.transform = 'perspective(800px) rotateX(0) rotateY(0) scale3d(1,1,1)';
        });
        card.style.transition = 'transform 0.5s ease-out';
    });

    // ─── GSAP SCROLL ANIMATIONS (replaces SectionWrapper) ──
    if (typeof gsap !== 'undefined' && typeof ScrollTrigger !== 'undefined') {
        gsap.registerPlugin(ScrollTrigger);

        // Hero stagger
        const heroTL = gsap.timeline({ delay: intro ? 8.5 : 0.5 });
        heroTL.fromTo('.hero-avatar', { opacity: 0, scale: 0.8 }, { opacity: 1, scale: 1, duration: 1, ease: 'back.out(1.7)' })
              .fromTo('.hero-name .char', { opacity: 0, y: 60, rotateX: -90, filter: 'blur(10px)' },
                { opacity: 1, y: 0, rotateX: 0, filter: 'blur(0)', duration: 0.8, stagger: 0.04, ease: 'power3.out' }, '-=0.5')
              .fromTo('.hero-subtitle', { opacity: 0, y: 30 }, { opacity: 1, y: 0, duration: 0.8 }, '-=0.3')
              .fromTo('.hero-cta', { opacity: 0, y: 20 }, { opacity: 1, y: 0, duration: 0.6 }, '-=0.2')
              .fromTo('.scroll-indicator', { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.6 }, '-=0.1');

        // Section reveals (like SectionWrapper with perspective + blur)
        gsap.utils.toArray('.gsap-section').forEach(section => {
            gsap.fromTo(section, 
                { opacity: 0, y: 80, filter: 'blur(10px)', rotateX: 10, scale: 0.95 },
                { opacity: 1, y: 0, filter: 'blur(0)', rotateX: 0, scale: 1, duration: 1.2, ease: 'power3.out',
                  scrollTrigger: { trigger: section, start: 'top 85%' }
                }
            );
        });

        // Skill pills stagger
        const skillContainer = document.querySelector('.skills-grid');
        if (skillContainer) {
            gsap.fromTo('.skill-pill', { opacity: 0, scale: 0.7, y: 20 },
                { opacity: 1, scale: 1, y: 0, duration: 0.5, stagger: 0.04, ease: 'back.out(1.7)',
                  scrollTrigger: { trigger: skillContainer, start: 'top 80%' }
                }
            );
        }

        // Project cards
        gsap.utils.toArray('.project-card').forEach((card, i) => {
            gsap.fromTo(card, { opacity: 0, y: 60, rotateY: i % 2 === 0 ? -5 : 5 },
                { opacity: 1, y: 0, rotateY: 0, duration: 1, ease: 'power3.out',
                  scrollTrigger: { trigger: card, start: 'top 85%' }
                }
            );
        });

        // Timeline items
        gsap.utils.toArray('.timeline-item').forEach(item => {
            gsap.fromTo(item, { opacity: 0, x: -30 },
                { opacity: 1, x: 0, duration: 0.8, ease: 'power3.out',
                  scrollTrigger: { trigger: item, start: 'top 85%' }
                }
            );
        });
    }

    // ─── TYPING EFFECT ─────────────────────────────────────
    const typeEl = document.getElementById('type-target');
    if (typeEl) {
        const words = JSON.parse(typeEl.dataset.words || '[]');
        let wordIndex = 0, charIndex = 0, deleting = false;

        function type() {
            const current = words[wordIndex];
            if (!deleting) {
                typeEl.textContent = current.substring(0, charIndex + 1);
                charIndex++;
                if (charIndex === current.length) {
                    setTimeout(() => { deleting = true; type(); }, 2000);
                    return;
                }
            } else {
                typeEl.textContent = current.substring(0, charIndex - 1);
                charIndex--;
                if (charIndex === 0) {
                    deleting = false;
                    wordIndex = (wordIndex + 1) % words.length;
                }
            }
            setTimeout(type, deleting ? 40 : 80);
        }
        if (words.length > 0) setTimeout(type, intro ? 9000 : 1500);
    }

    // ─── INTERACTIVE PROFILE RIG ───────────────────────────
    const rig = document.querySelector('.profile-rig');
    if (rig) {
        rig.addEventListener('mousemove', e => {
            const rect = rig.getBoundingClientRect();
            const x = (e.clientX - rect.left) / rect.width - 0.5;
            const y = (e.clientY - rect.top) / rect.height - 0.5;
            rig.style.transform = `rotateY(${x * 20}deg) rotateX(${-y * 20}deg)`;
        });
        rig.addEventListener('mouseleave', () => {
            rig.style.transform = 'rotateY(0) rotateX(0)';
        });
        rig.style.transition = 'transform 0.4s cubic-bezier(.25,1,.5,1)';
        rig.style.transformStyle = 'preserve-3d';
    }

    // ─── SMOOTH SCROLL ─────────────────────────────────────
    document.querySelectorAll('a[href^="#"]').forEach(a => {
        a.addEventListener('click', e => {
            e.preventDefault();
            const el = document.querySelector(a.getAttribute('href'));
            if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    });

})();
