<?php // Auto-generated Full Data Template: Finance_pro ?>
<!DOCTYPE html>
<html lang="en" class="scroll-smooth">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= htmlspecialchars($d["name"]) ?> | <?= htmlspecialchars($d["job_title"]) ?></title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url("https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&family=Space+Grotesk:wght@400;700&family=Poppins:wght@300;500;700&family=Fira+Code&family=Press+Start+2P&family=Outfit:wght@400;900&family=Playfair+Display:ital,wght@0,400;1,700&family=Bebas+Neue&family=Montserrat:wght@300;400;700;900&family=Lora:ital,wght@0,400;1,700&family=Ubuntu+Mono&display=swap");
        body { font-family: "Inter", sans-serif; }
        section { scroll-margin-top: 100px; }
        .nav-link { position: relative; transition: opacity 0.3s; }
        .nav-link::after { content: ""; position: absolute; bottom: -4px; left: 0; width: 0; height: 2px; background: currentColor; transition: width 0.3s; }
        .nav-link:hover::after { width: 100%; }
        .fade-in { animation: fadeIn 1s ease-out forwards; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body class="bg-white text-slate-800 antialiased selection:bg-yellow-400 selection:text-black">

<!-- NAVIGATION BAR -->
<nav class="fixed top-0 left-0 right-0 z-50 bg-white backdrop-blur-md border-b border-current/10 py-4">
    <div class="max-w-7xl mx-auto px-6 flex justify-between items-center">
        <div class="font-bold text-xl tracking-tighter cursor-pointer" onclick="window.scrollTo({top:0, behavior:'smooth'})"><?= htmlspecialchars($d["name"]) ?></div>
        <div class="hidden md:flex gap-8 text-sm font-medium uppercase tracking-widest opacity-70">
            <a href="#about" class="nav-link">About</a>
            <a href="#experience" class="nav-link">Experience</a>
            <a href="#projects" class="nav-link">Projects</a>
            <a href="#skills" class="nav-link">Skills</a>
            <a href="#certificates" class="nav-link">Certificates</a>
            <a href="#achievements" class="nav-link">Awards</a>
        </div>
        <a href="mailto:<?= htmlspecialchars($d["email"]) ?>" class="bg-slate-900 text-white px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-tighter hover:opacity-80 transition-opacity">Hire Me</a>
    </div>
</nav>

<div class="max-w-5xl mx-auto px-8 py-20 pt-32">

    <!-- HERO SECTION -->
    <header id="home" class="mb-24 flex flex-col md:flex-row items-center md:items-start gap-12 fade-in">
        <svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" class="w-56 h-56 object-cover rounded-2xl border-4 border-current shadow-2xl">
            <defs>
                <linearGradient id="hero-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" style="stop-color:currentColor;stop-opacity:0.8" />
                    <stop offset="100%" style="stop-color:currentColor;stop-opacity:0.4" />
                </linearGradient>
                <style>
                    @keyframes hero-float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-12px); } }
                    .hero-shape { animation: hero-float 3s ease-in-out infinite; }
                </style>
            </defs>
            <circle cx="50" cy="35" r="20" class="hero-shape" fill="url(#hero-grad)"/>
            <ellipse cx="50" cy="70" rx="25" ry="20" class="hero-shape" fill="url(#hero-grad)" opacity="0.6"/>
            <circle cx="35" cy="25" r="5" fill="currentColor" opacity="0.3"/>
            <circle cx="65" cy="28" r="5" fill="currentColor" opacity="0.3"/>
        </svg>
        <div class="text-center md:text-left">
            <h1 class="text-6xl md:text-8xl font-bold mb-4 tracking-tighter"><?= htmlspecialchars($d["name"]) ?></h1>
            <h2 class="text-3xl md:text-4xl text-blue-900 mb-6"><?= htmlspecialchars($d["job_title"]) ?></h2>
            <div class="flex flex-wrap justify-center md:justify-start gap-6 mb-8 text-lg">
                <?php if($d["location"]): ?><span class="opacity-80"><i class="fas fa-map-marker-alt mr-2"></i> <?= htmlspecialchars($d["location"]) ?></span><?php endif; ?>
                <?php if($d["email"]): ?><a href="mailto:<?= htmlspecialchars($d["email"]) ?>" class="hover:underline opacity-80"><i class="fas fa-envelope mr-2"></i> <?= htmlspecialchars($d["email"]) ?></a><?php endif; ?>
                <?php if($d["phone"]): ?><span class="opacity-80"><i class="fas fa-phone mr-2"></i> <?= htmlspecialchars($d["phone"]) ?></span><?php endif; ?>
            </div>
            <?php if(!empty($d["social"])): ?>
            <div class="flex justify-center md:justify-start gap-6 text-2xl">
                <?php foreach($d["social"] as $s): ?>
                <a href="<?= htmlspecialchars($s["url"]) ?>" class="hover:text-current opacity-70 hover:opacity-100 transition-opacity"><i class="fab fa-<?= htmlspecialchars($s["platform"]) ?>"></i></a>
                <?php endforeach; ?>
            </div>
            <?php endif; ?>
        </div>
    </header>

    <!-- ABOUT SECTION -->
    <?php if(!empty($d["bio"]) && ($d["sections"]["about"] ?? true)): ?>
    <section id="about" class="mb-24 fade-in" style="animation-delay:0.2s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">About Me</h3>
        <div class="text-xl leading-relaxed opacity-90 max-w-4xl">
            <?= nl2br(htmlspecialchars($d["bio"])) ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- EXPERIENCE SECTION -->
    <?php if(!empty($d["experience"]) && ($d["sections"]["experience"] ?? true)): ?>
    <section id="experience" class="mb-24 fade-in" style="animation-delay:0.4s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">Experience</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <?php foreach($d["experience"] as $exp): ?>
            <div class="bg-white border border-slate-200 p-8 shadow-sm group">
                <div class="flex justify-between items-start mb-4">
                    <h4 class="text-2xl font-bold group-hover:text-blue-900 transition-colors"><?= htmlspecialchars($exp["title"]) ?></h4>
                    <span class="text-sm font-bold opacity-70 bg-current/10 px-3 py-1 rounded"><?= htmlspecialchars($exp["period"]) ?></span>
                </div>
                <h5 class="text-lg text-blue-900 mb-4"><?= htmlspecialchars($exp["company"]) ?></h5>
                <p class="opacity-80 leading-relaxed"><?= htmlspecialchars($exp["description"]) ?></p>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- PROJECTS SECTION -->
    <?php if(!empty($d["projects"]) && ($d["sections"]["projects"] ?? true)): ?>
    <section id="projects" class="mb-24 fade-in" style="animation-delay:0.6s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">Projects</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <?php foreach($d["projects"] as $proj): ?>
            <div class="bg-white border border-slate-200 p-8 shadow-sm flex flex-col h-full group">
                <h4 class="text-2xl font-bold mb-3 group-hover:scale-105 origin-left transition-transform"><?= htmlspecialchars($proj["title"]) ?></h4>
                <p class="opacity-80 flex-grow mb-6"><?= htmlspecialchars($proj["description"]) ?></p>
                <div class="mt-auto">
                    <?php 
                    $techs = is_array($proj["tech"]) ? $proj["tech"] : explode(",", $proj["tech"]);
                    foreach($techs as $tech): 
                    ?>
                        <span class="text-xs font-mono opacity-60 uppercase border border-current/20 px-2 py-1 mr-1 mb-1 inline-block"><?= htmlspecialchars(trim($tech)) ?></span>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- SKILLS SECTION -->
    <?php if(!empty($d["skills"]) && ($d["sections"]["skills"] ?? true)): ?>
    <section id="skills" class="mb-24 fade-in" style="animation-delay:0.8s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">Skills & Technologies</h3>
        <div class="flex flex-wrap gap-4">
            <?php foreach($d["skills"] as $skill): ?>
            <span class="px-3 py-1 bg-slate-100 border border-slate-200 text-slate-600 text-sm mr-2 mb-2 inline-block hover:scale-110 transition-transform"><?= htmlspecialchars($skill) ?></span>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- CERTIFICATES SECTION -->
    <?php if(!empty($d["certificates"]) && ($d["sections"]["certifications"] ?? true)): ?>
    <section id="certificates" class="mb-24 fade-in" style="animation-delay:1s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">Certifications</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <?php foreach($d["certificates"] as $cert): ?>
            <div class="bg-white border border-slate-200 p-8 shadow-sm">
                <div class="flex justify-between items-start mb-2">
                    <h4 class="font-bold text-xl"><?= htmlspecialchars($cert["name"]) ?></h4>
                    <span class="text-xs font-mono py-1 px-2 rounded bg-current/5"><?= htmlspecialchars($cert["date"]) ?></span>
                </div>
                <p class="opacity-70"><?= htmlspecialchars($cert["issuer"]) ?></p>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- ACHIEVEMENTS SECTION -->
    <?php if(!empty($d["achievements"]) && ($d["sections"]["achievements"] ?? true)): ?>
    <section id="achievements" class="mb-24 fade-in" style="animation-delay:1.1s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">Achievements & Awards</h3>
        <div class="grid grid-cols-1 gap-4">
            <?php foreach($d["achievements"] as $ach): ?>
            <div class="flex items-start gap-4 p-6 border-l-4 border-current bg-current/5">
                <i class="fas fa-trophy mt-1 text-blue-900"></i>
                <span class="text-lg opacity-90"><?= htmlspecialchars($ach) ?></span>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- GET IN TOUCH SECTION -->
    <?php if($d["sections"]["contact"] ?? true): ?>
    <section id="contact" class="mb-24 fade-in text-center" style="animation-delay:1.2s">
        <h3 class="text-3xl font-bold mb-10 text-slate-900">Get In Touch</h3>
        <p class="text-xl opacity-70 mb-10 max-w-2xl mx-auto">Have a project in mind or just want to say hi? I'd love to hear from you!</p>
        <div class="flex flex-wrap justify-center gap-8">
            <a href="mailto:<?= htmlspecialchars($d["email"]) ?>" class="bg-slate-900 text-white px-10 py-5 rounded-full text-lg font-bold uppercase tracking-widest hover:scale-105 transition-transform inline-flex items-center gap-3">
                <i class="fas fa-paper-plane"></i> Send Message
            </a>
            <div class="flex items-center gap-6 text-2xl">
                <?php if(!empty($d["social"])): ?>
                    <?php foreach($d["social"] as $s): ?>
                        <a href="<?= htmlspecialchars($s["url"]) ?>" class="hover:text-current opacity-60 hover:opacity-100 transition-opacity"><i class="fab fa-<?= htmlspecialchars($s["platform"]) ?>"></i></a>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </section>
    <?php endif; ?>

    <footer class="pt-12 border-t border-current/10 flex flex-col md:flex-row justify-between items-center opacity-40 text-sm">
        <p>&copy; <?= date("Y") ?> <?= htmlspecialchars($d["name"]) ?>. All rights reserved.</p>
        <div class="font-mono mt-4 md:mt-0">Built with CreativePort Engine</div>
    </footer>

</div>

<!-- Floating Action Buttons -->
<div class="fixed bottom-10 right-10 flex flex-col gap-4 z-50 no-print">
    <button onclick="window.print()" class="w-16 h-16 rounded-full bg-white text-black shadow-2xl flex items-center justify-center hover:scale-110 active:scale-95 transition-all border border-black/10 group" title="Export as PDF">
        <i class="fas fa-file-pdf text-xl group-hover:rotate-12 transition-transform"></i>
    </button>
    <button onclick="sharePortfolio()" class="bg-slate-900 text-white w-16 h-16 rounded-full shadow-2xl flex items-center justify-center hover:scale-110 active:scale-95 transition-all group" title="Share Portfolio">
        <i class="fas fa-share-alt text-xl group-hover:-rotate-12 transition-transform"></i>
    </button>
</div>

<div id="toast" class="fixed top-10 right-10 px-8 py-4 bg-black text-white rounded-full transform translate-x-[150%] transition-all duration-500 z-[100] shadow-2xl border border-white/10 text-xs font-black uppercase tracking-widest"></div>

<script>
    function showToast(msg) {
        const t = document.getElementById("toast");
        t.textContent = msg;
        t.classList.remove("translate-x-[150%]");
        setTimeout(() => t.classList.add("translate-x-[150%]"), 3000);
    }
    function sharePortfolio() {
        const url = window.location.href;
        if (navigator.share) {
            navigator.share({ title: "<?= htmlspecialchars($d["name"]) ?> | Portfolio", url: url });
        } else {
            navigator.clipboard.writeText(url).then(() => showToast("Link copied to clipboard!"));
        }
    }
</script>

<style>
    @media print { .no-print { display: none !important; } }
    html { scroll-behavior: smooth; }
    .fade-in { animation: fadeIn 0.8s ease-out forwards; opacity: 0; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
</style>

</body>
</html>
