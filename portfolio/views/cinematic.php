<?php

// Split name into chars for stagger animation
if (!function_exists("splitChars")) {
    function splitChars($text) {
        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $out = '';
        foreach ($chars as $c) {
            $class = $c === " " ? "char inline-block w-4" : "char inline-block";
            $out .= '<span class="' . $class . '">' . htmlspecialchars($c === " " ? "\u{00A0}" : $c) . "</span>";
        }
        return $out;
    }
}

// Build typing words from job_title
$typeWords = [$d['job_title'] ?: 'Developer'];
if (!empty($d['skills'])) {
    $typeWords[] = implode(' · ', array_slice($d['skills'], 0, 3)) . ' Expert';
}
$typeWords[] = 'Problem Solver';
?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($d['name']) ?> | <?= htmlspecialchars($d['job_title'] ?: 'Portfolio') ?></title>
    <meta name="description" content="<?= htmlspecialchars(substr($d['bio'], 0, 160)) ?>">
    
    <!-- Open Graph / Social SEO -->
    <meta property="og:type" content="profile">
    <meta property="og:title" content="<?= htmlspecialchars($d['name']) ?> | <?= htmlspecialchars($d['job_title'] ?: 'Portfolio') ?>">
    <meta property="og:description" content="<?= htmlspecialchars(substr($d['bio'], 0, 160)) ?>">
    <meta property="og:url" content="<?= "http://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'] ?>">
    <meta property="og:image" content="https://images.unsplash.com/photo-1555066931-4365d14bab8c?auto=format&fit=crop&q=80&w=1200&h=630">
    <meta name="twitter:card" content="summary_large_image">
    
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Poppins:wght@300;400;500;600;700;800;900&family=Fira+Code:wght@400;500&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/gsap.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.2/ScrollTrigger.min.js"></script>
    <link rel="stylesheet" href="portfolio/cinematic.css">
    <style>
        section, .gsap-section { scroll-margin-top: 100px; }
        .hero-social-link { position: relative; z-index: 10; }
        /* Add some specific styles for the centered hero without avatar */
        .hero { display: flex; flex-direction: column; align-items: center; justify-content: center; text-align: center; }
        .hero-name { margin-top: 2rem; }
    </style>
</head>
<body>

    <!-- Cursor System -->
    <div class="cursor-glow" id="cursorGlow"></div>
    <div class="cursor-ring" id="cursorRing"></div>
    <div class="cursor-dot" id="cursorDot"></div>
    <div class="cursor-text" id="cursorText"></div>

    <!-- Background Systems -->
    <canvas id="particle-canvas"></canvas>
    <div class="bg-grid"></div>

    <!-- NAVIGATION BAR -->
    <nav class="fixed top-0 left-0 right-0 z-[500] px-8 py-6 flex justify-between items-center mix-blend-difference pointer-events-none">
        <div class="font-bold text-xl tracking-widest uppercase pointer-events-auto interactable" data-cursor="HOME" onclick="window.scrollTo({top:0, behavior:'smooth'})"><?= htmlspecialchars(explode(' ', $d['name'])[0]) ?></div>
        <div class="hidden md:flex gap-10 text-[10px] font-bold uppercase tracking-[0.3em] pointer-events-auto">
            <a href="#about" class="interactable hover:text-yellow-500 transition-colors" data-cursor="ABOUT">About</a>
            <a href="#skills" class="interactable hover:text-yellow-500 transition-colors" data-cursor="TECH">Skills</a>
            <a href="#projects" class="interactable hover:text-yellow-500 transition-colors" data-cursor="WORK">Work</a>
            <a href="#experience" class="interactable hover:text-yellow-500 transition-colors" data-cursor="HISTORY">Experience</a>
            <a href="#certificates" class="interactable hover:text-yellow-500 transition-colors" data-cursor="CERTS">Certs</a>
            <a href="#contact" class="interactable hover:text-yellow-500 transition-colors" data-cursor="CONNECT">Contact</a>
        </div>
        <div class="pointer-events-auto">
            <a href="mailto:<?= htmlspecialchars($d['email']) ?>" class="interactable" data-cursor="HIRE"><i class="fas fa-envelope text-xl"></i></a>
        </div>
    </nav>

    <!-- ═══ HERO ═══ -->
    <section class="hero" id="home">
        <div class="profile-rig hero-avatar" data-cursor="WHO AM I?">
            <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" style="width: 100%; height: 100%; filter: drop-shadow(0 0 20px rgba(100,200,255,0.3));">
                <defs>
                    <linearGradient id="cinematic-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" style="stop-color:#00d4ff;stop-opacity:1" />
                        <stop offset="100%" style="stop-color:#0099ff;stop-opacity:1" />
                    </linearGradient>
                    <style>
                        @keyframes cinematic-float { 0%, 100% { transform: translateY(0px) scale(1); } 50% { transform: translateY(-15px) scale(1.05); } }
                        @keyframes cinematic-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.8; } }
                        .cinematic-avatar { animation: cinematic-float 3s ease-in-out infinite; }
                        .cinematic-accent { animation: cinematic-pulse 2.5s ease-in-out infinite; }
                    </style>
                </defs>
                <!-- Head -->
                <circle cx="50" cy="30" r="22" class="cinematic-avatar" fill="url(#cinematic-grad)" opacity="0.9"/>
                <!-- Body -->
                <ellipse cx="50" cy="72" rx="28" ry="22" class="cinematic-avatar" fill="url(#cinematic-grad)" opacity="0.7"/>
                <!-- Tech accents -->
                <circle cx="30" cy="20" r="4" class="cinematic-accent" fill="#00d4ff" opacity="0.6"/>
                <circle cx="70" cy="22" r="4" class="cinematic-accent" fill="#0099ff" opacity="0.6"/>
                <!-- Center dot -->
                <circle cx="50" cy="50" r="2" fill="#00d4ff"/>
            </svg>
            <div class="orbital-ring"></div>
            <div class="orbital-ring-2"></div>
            <?php if (!empty($d['skills'])): ?>
            <div class="float-badge float-badge-1">🚀 <?= htmlspecialchars($d['skills'][0] ?? '') ?></div>
            <?php if (count($d['skills']) > 1): ?>
            <div class="float-badge float-badge-2">✨ <?= htmlspecialchars($d['skills'][1] ?? '') ?></div>
            <?php endif; ?>
            <?php if (count($d['skills']) > 2): ?>
            <div class="float-badge float-badge-3">⚡ <?= htmlspecialchars($d['skills'][2] ?? '') ?></div>
            <?php endif; ?>
            <?php endif; ?>
        </div>

        <p class="section-label hero-avatar" style="margin-bottom:.5rem">Welcome to my universe</p>

        <h1 class="hero-name" style="font-family:'Poppins',sans-serif">
            <?= splitChars($d['name']) ?>
        </h1>

        <div class="hero-subtitle">
            <span id="type-target" data-words='<?= json_encode($typeWords) ?>'></span>
            <span class="animate-pulse" style="color:var(--cyan)">|</span>
        </div>

        <?php if (!empty($d['social'])): ?>
        <div class="flex gap-6 mt-8 mb-4 text-2xl relative z-10">
            <?php foreach ($d['social'] as $s): ?>
                <a href="<?= htmlspecialchars($s['url']) ?>" class="interactable opacity-50 hover:opacity-100 transition-opacity hover:text-yellow-500 hero-social-link" target="_blank" data-cursor="<?= strtoupper($s['platform']) ?>">
                    <i class="fab fa-<?= htmlspecialchars($s['platform']) ?>"></i>
                </a>
            <?php endforeach; ?>
        </div>
        <?php endif; ?>

        <?php if ($d['bio']): ?>
        <p class="hero-role" style="max-width:600px;line-height:2;margin-top:2rem;text-align:center;color:rgba(255,255,255,.4);font-weight:300">
            <?= htmlspecialchars($d['bio']) ?>
        </p>
        <?php endif; ?>

        <div class="magnetic-wrap hero-cta" style="margin-top:2rem">
            <a href="#about" class="btn-cta interactable" data-cursor="EXPLORE">
                <div class="btn-fill"></div>
                <span>Discover My Story <i class="fas fa-arrow-down ml-2"></i></span>
            </a>
        </div>

        <div class="scroll-indicator">
            <div class="scroll-mouse"><div class="scroll-dot"></div></div>
        </div>
    </section>

    <!-- ═══ ABOUT ═══ -->
    <?php if (!empty($d['bio']) && ($d['sections']['about'] ?? true)): ?>
    <section id="about" class="section-container gsap-section" style="perspective:1000px">
        <div class="section-label">01. Biography</div>
        <h2 class="section-title">About Me</h2>
        
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-12 items-start">
            <div class="text-lg leading-relaxed" style="color:rgba(226,232,240,.6);font-weight:300">
                <?= nl2br(htmlspecialchars($d['bio'])) ?>
            </div>
            <div class="glass p-8 tilt-card interactable" data-cursor="INFO">
                <div class="card-glow"></div>
                <h4 class="text-xl font-bold mb-6 relative z-10">Quick Facts</h4>
                <ul class="space-y-4 font-mono text-sm relative z-10" style="color:rgba(255,255,255,.5)">
                    <?php if ($d['location']): ?><li class="flex justify-between border-b border-white/5 pb-3"><span>Location</span><span class="text-white"><?= htmlspecialchars($d['location']) ?></span></li><?php endif; ?>
                    <?php if ($d['email']): ?><li class="flex justify-between border-b border-white/5 pb-3"><span>Email</span><span class="text-white"><?= htmlspecialchars($d['email']) ?></span></li><?php endif; ?>
                    <li class="flex justify-between pb-3"><span>Status</span><span style="color:#10b981">Available for hire</span></li>
                    <?php if ($d['score']): ?><li class="flex justify-between pb-3"><span>Portfolio Score</span><span style="color:var(--cyan)"><?= $d['score'] ?>/100</span></li><?php endif; ?>
                </ul>
            </div>
        </div>
    </section>
    <?php endif; ?>

    <!-- ═══ SKILLS ═══ -->
    <?php if (!empty($d['skills']) && ($d['sections']['skills'] ?? true)): ?>
    <section id="skills" class="section-container gsap-section">
        <div class="section-label">02. Tech Stack</div>
        <h2 class="section-title">Technologies I Use</h2>
        <div class="skills-grid flex flex-wrap gap-4">
            <?php foreach ($d['skills'] as $skill): ?>
                <div class="skill-pill interactable"><i class="fas fa-code" style="color:var(--cyan);font-size:.7rem"></i> <?= htmlspecialchars($skill) ?></div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- ═══ PROJECTS ═══ -->
    <?php if (!empty($d['projects']) && ($d['sections']['projects'] ?? true)): ?>
    <section id="projects" class="section-container gsap-section">
        <div class="section-label">03. Work</div>
        <h2 class="section-title">Featured Projects</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <?php foreach ($d['projects'] as $p): ?>
            <div class="project-card tilt-card p-8 interactable" data-cursor="VIEW">
                <div class="card-glow"></div>
                <div class="relative z-10">
                    <p class="font-mono text-xs mb-3" style="color:var(--cyan)">Featured Project</p>
                    <h3 class="text-2xl font-bold mb-4"><?= htmlspecialchars($p['title'] ?? 'Untitled') ?></h3>
                    <p class="text-sm mb-6" style="color:rgba(255,255,255,.45);line-height:1.8"><?= htmlspecialchars($p['description'] ?? '') ?></p>
                    <?php if (!empty($p['tech'])): ?>
                    <div class="flex flex-wrap gap-2 mb-6">
                        <?php $techs = is_array($p['tech']) ? $p['tech'] : explode(',', $p['tech']);
                        foreach ($techs as $t): ?>
                            <span class="font-mono text-xs px-3 py-1 rounded-full" style="background:rgba(255,255,255,.04);color:rgba(255,255,255,.5)"><?= htmlspecialchars(trim($t)) ?></span>
                        <?php endforeach; ?>
                    </div>
                    <?php endif; ?>
                    <?php if (!empty($p['link'])): ?>
                    <a href="<?= htmlspecialchars($p['link']) ?>" target="_blank" class="inline-flex items-center gap-2 text-sm interactable" style="color:var(--cyan)">
                        <i class="fab fa-github"></i> View Repository
                    </a>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- ═══ EXPERIENCE ═══ -->
    <?php if (!empty($d['experience']) && ($d['sections']['experience'] ?? true)): ?>
    <section id="experience" class="section-container gsap-section">
        <div class="section-label">04. Timeline</div>
        <h2 class="section-title">Work Experience</h2>
        <div class="timeline max-w-3xl">
            <?php foreach ($d['experience'] as $exp): ?>
            <div class="timeline-item">
                <div class="timeline-dot"></div>
                <p class="font-mono text-sm mb-1" style="color:var(--cyan)"><?= htmlspecialchars($exp['period'] ?? '') ?></p>
                <h3 class="text-xl font-bold"><?= htmlspecialchars($exp['title'] ?? '') ?></h3>
                <h4 class="text-lg mb-3" style="color:rgba(255,255,255,.4)"><?= htmlspecialchars($exp['company'] ?? '') ?></h4>
                <p style="color:rgba(255,255,255,.35);font-weight:300"><?= htmlspecialchars($exp['description'] ?? '') ?></p>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- ═══ CERTIFICATES ═══ -->
    <?php if (!empty($d['certificates']) && ($d['sections']['certifications'] ?? true)): ?>
    <section id="certificates" class="section-container gsap-section">
        <div class="section-label">05. Credentials</div>
        <h2 class="section-title">Certifications</h2>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <?php foreach ($d['certificates'] as $cert): ?>
            <div class="glass p-5 rounded-xl border border-white/5 hover:border-yellow-500/30 transition-colors interactable" data-cursor="VIEW">
                <div class="flex justify-between items-start mb-2">
                    <h4 class="font-bold text-white"><?= htmlspecialchars($cert['name'] ?? '') ?></h4>
                    <span class="text-xs font-mono py-1 px-2 rounded bg-yellow-500/10 text-yellow-500"><?= htmlspecialchars($cert['date'] ?? '') ?></span>
                </div>
                <p class="text-sm text-neutral-400"><i class="fas fa-building mr-1"></i> <?= htmlspecialchars($cert['issuer'] ?? '') ?></p>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- ═══ ACHIEVEMENTS ═══ -->
    <?php if (!empty($d['achievements']) && ($d['sections']['achievements'] ?? true)): ?>
    <section id="achievements" class="section-container gsap-section">
        <div class="section-label">06. Awards</div>
        <h2 class="section-title">Key Achievements</h2>
        <div class="glass p-8 rounded-3xl border border-white/5 bg-white/2 max-w-4xl">
            <ul class="space-y-6">
                <?php foreach ($d['achievements'] as $ach): ?>
                <li class="flex items-start gap-4 text-lg text-neutral-300">
                    <i class="fas fa-trophy text-yellow-500 mt-1"></i>
                    <span class="leading-relaxed"><?= htmlspecialchars($ach) ?></span>
                </li>
                <?php endforeach; ?>
            </ul>
        </div>
    </section>
    <?php endif; ?>

    <!-- ═══ CONTACT / GET IN TOUCH ═══ -->
    <?php if ($d['sections']['contact'] ?? true): ?>
    <section id="contact" class="section-container gsap-section text-center">
        <div class="section-label">07. Connect</div>
        <h2 class="section-title">Get In Touch</h2>
        <p class="text-xl mb-12 mx-auto max-w-2xl opacity-50 font-light">Have a vision? Let\'s bring it to life through code and design.</p>
        
        <div class="magnetic-wrap inline-block">
            <a href="mailto:<?= htmlspecialchars($d['email']) ?>" class="btn-cta interactable px-12 py-6 rounded-full bg-yellow-500 text-black font-bold uppercase tracking-widest text-lg shadow-[0_0_40px_rgba(234,179,8,0.2)] hover:scale-105 transition-transform" data-cursor="EMAIL">
                <span><i class="fas fa-paper-plane mr-2"></i> Send Message</span>
            </a>
        </div>

        <div class="mt-16 flex justify-center gap-8 text-2xl opacity-60">
            <?php if(!empty($d["social"])): ?>
                <?php foreach($d["social"] as $s): ?>
                    <a href="<?= htmlspecialchars($s["url"]) ?>" class="hover:text-yellow-500 transition-colors interactable" data-cursor="<?= strtoupper($s["platform"]) ?>"><i class="fab fa-<?= htmlspecialchars($s["platform"]) ?>"></i></a>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </section>
    <?php endif; ?>

    <footer class="footer">
        <p>Designed & Built with <a href="../index.html" style="color:var(--cyan)" class="interactable">CreativePort</a> Engine</p>
    </footer>

    <!-- Floating Action Buttons for Share & Export -->
    <div class="fab-container fixed bottom-6 right-6 flex flex-col gap-3 z-50">
        <button onclick="window.print()" class="w-12 h-12 rounded-full bg-neutral-900 border border-white/10 text-white flex items-center justify-center shadow-lg hover:border-yellow-500 hover:text-yellow-500 transition-colors interactable" title="Save as PDF">
            <i class="fas fa-file-pdf"></i>
        </button>
        <button onclick="sharePortfolio()" class="w-12 h-12 rounded-full bg-yellow-500 text-black flex items-center justify-center shadow-lg shadow-yellow-500/20 hover:scale-110 transition-transform interactable" title="Share Portfolio">
            <i class="fas fa-share-alt"></i>
        </button>
    </div>

    <!-- Toast Notification -->
    <div id="toast" class="fixed top-6 right-6 px-6 py-3 rounded-lg bg-neutral-900 border border-yellow-500/30 text-yellow-500 transform transition-all duration-300 translate-x-full opacity-0 z-50 font-medium text-sm shadow-2xl"></div>

    <script src="<?= $assetsPath ?>cinematic.js"></script>
    <script>
        function showToast(msg) {
            const toast = document.getElementById('toast');
            toast.textContent = msg;
            toast.classList.remove('translate-x-full', 'opacity-0');
            setTimeout(() => toast.classList.add('translate-x-full', 'opacity-0'), 3000);
        }

        async function sharePortfolio() {
            const url = window.location.href;
            if (navigator.share) {
                try {
                    await navigator.share({
                        title: '<?= htmlspecialchars($d['name']) ?> | Portfolio',
                        text: 'Check out my professional portfolio!',
                        url: url
                    });
                } catch(e) { console.error('Share failed', e); }
            } else {
                navigator.clipboard.writeText(url).then(() => {
                    showToast("Link copied to clipboard!");
                }).catch(() => {
                    showToast("Failed to copy link.");
                });
            }
        }
    </script>
</body>
</html>
