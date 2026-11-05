<?php
// Mega Template Generator for 39 distinct rich templates (Total 40 including Cinematic)
$viewsDir = __DIR__ . '/portfolio/views';

$configs = [
    'minimal' => [
        'bg' => 'bg-white', 'text' => 'text-black', 'accent' => 'text-gray-500', 'font' => 'Inter',
        'container' => 'max-w-4xl mx-auto px-8 py-24',
        'heading' => 'text-4xl font-light mb-12 tracking-tight border-b pb-4',
        'card' => 'mb-8', 'skill_badge' => 'px-3 py-1 border border-gray-200 text-sm mb-2 mr-2 inline-block',
        'nav_bg' => 'bg-white/80', 'btn_bg' => 'bg-black', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'creative' => [
        'bg' => 'bg-[#ffebd2]', 'text' => 'text-[#ff4500]', 'accent' => 'text-black', 'font' => 'Space Grotesk',
        'container' => 'w-full px-12 py-24',
        'heading' => 'text-6xl font-black mb-16 uppercase tracking-tighter',
        'card' => 'bg-[#ff4500] text-[#ffebd2] p-8 hover:-translate-y-2 transition-transform shadow-[8px_8px_0_black]',
        'skill_badge' => 'px-4 py-2 bg-black text-white font-bold uppercase mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-[#ffebd2]/90', 'btn_bg' => 'bg-[#ff4500]', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'modern' => [
        'bg' => 'bg-gradient-to-br from-indigo-900 via-purple-900 to-black', 'text' => 'text-white', 'accent' => 'text-purple-300', 'font' => 'Poppins',
        'container' => 'max-w-6xl mx-auto px-8 py-24',
        'heading' => 'text-5xl font-bold mb-16 bg-clip-text text-transparent bg-gradient-to-r from-purple-400 to-pink-600',
        'card' => 'bg-white/5 backdrop-blur-lg border border-white/10 p-8 rounded-2xl hover:bg-white/10 transition-colors',
        'skill_badge' => 'px-4 py-1.5 bg-white/10 rounded-full text-sm font-medium mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-black/50', 'btn_bg' => 'bg-white', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'neobrutalism' => [
        'bg' => 'bg-[#bbf7d0]', 'text' => 'text-black', 'accent' => 'text-indigo-800', 'font' => 'Space Grotesk',
        'container' => 'max-w-5xl mx-auto px-6 py-20',
        'heading' => 'text-5xl font-black mb-12 uppercase border-b-4 border-black pb-4',
        'card' => 'bg-white border-4 border-black p-8 shadow-[8px_8px_0_black] hover:translate-x-1 hover:translate-y-1 hover:shadow-[4px_4px_0_black] transition-all',
        'skill_badge' => 'px-3 py-1 bg-yellow-400 border-2 border-black font-bold mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-white', 'btn_bg' => 'bg-black', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'cyberpunk' => [
        'bg' => 'bg-[#050505]', 'text' => 'text-[#00ffcc]', 'accent' => 'text-[#ff00ff]', 'font' => 'Fira Code',
        'container' => 'max-w-6xl mx-auto px-8 py-20 border-l-2 border-r-2 border-[#ff00ff]/30',
        'heading' => 'text-4xl font-bold mb-12 uppercase tracking-widest border-b border-[#00ffcc] pb-4',
        'card' => 'bg-black border border-[#00ffcc]/50 p-6 hover:bg-[#00ffcc]/10 hover:border-[#00ffcc] transition-colors',
        'skill_badge' => 'px-2 py-1 text-xs border border-[#ff00ff] text-[#ff00ff] mr-2 mb-2 inline-block uppercase',
        'nav_bg' => 'bg-black/80', 'btn_bg' => 'bg-[#00ffcc]', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'bento' => [
        'bg' => 'bg-[#f5f5f7]', 'text' => 'text-gray-900', 'accent' => 'text-blue-600', 'font' => 'Inter',
        'container' => 'max-w-6xl mx-auto px-6 py-20',
        'heading' => 'text-3xl font-semibold mb-8 pl-4 border-l-4 border-blue-500',
        'card' => 'bg-white rounded-[32px] p-8 shadow-[0_8px_30px_rgb(0,0,0,0.04)] hover:shadow-[0_8px_30px_rgb(0,0,0,0.08)] transition-shadow',
        'skill_badge' => 'px-4 py-2 bg-gray-100 rounded-xl text-sm font-medium mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-white/70', 'btn_bg' => 'bg-blue-600', 'btn_text' => 'text-white', 'layout' => 'grid'
    ],
    'corporate' => [
        'bg' => 'bg-slate-50', 'text' => 'text-slate-800', 'accent' => 'text-blue-800', 'font' => 'Inter',
        'container' => 'max-w-5xl mx-auto px-8 py-20',
        'heading' => 'text-3xl font-bold mb-10 text-slate-900',
        'card' => 'bg-white border border-slate-200 p-8 shadow-sm',
        'skill_badge' => 'px-3 py-1 bg-slate-100 border border-slate-200 text-slate-600 text-sm mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-white', 'btn_bg' => 'bg-slate-900', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'developer' => [
        'bg' => 'bg-[#1e1e1e]', 'text' => 'text-[#d4d4d4]', 'accent' => 'text-[#569cd6]', 'font' => 'Fira Code',
        'container' => 'max-w-4xl mx-auto px-6 py-12',
        'heading' => 'text-2xl font-bold mb-8 text-[#569cd6]',
        'card' => 'border-l-2 border-[#404040] pl-6 mb-8',
        'skill_badge' => 'text-[#ce9178] mr-4 mb-2 inline-block',
        'nav_bg' => 'bg-[#1e1e1e]/90', 'btn_bg' => 'bg-[#569cd6]', 'btn_text' => 'text-white', 'layout' => 'split'
    ],
    'retro' => [
        'bg' => 'bg-[#0000aa]', 'text' => 'text-white', 'accent' => 'text-[#ffff55]', 'font' => 'Press Start 2P',
        'container' => 'max-w-4xl mx-auto px-6 py-16',
        'heading' => 'text-xl mb-12 text-[#ffff55] text-center',
        'card' => 'border-4 border-white bg-black p-6 mb-8 shadow-[8px_8px_0_#555]',
        'skill_badge' => 'text-[#55ff55] mr-4 mb-4 inline-block text-xs',
        'nav_bg' => 'bg-[#0000aa]', 'btn_bg' => 'bg-[#ffff55]', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'photography' => [
        'bg' => 'bg-[#111]', 'text' => 'text-gray-300', 'accent' => 'text-white', 'font' => 'Inter',
        'container' => 'w-full max-w-[1400px] mx-auto px-8 py-24',
        'heading' => 'text-6xl font-light mb-16 tracking-widest uppercase text-center',
        'card' => 'border-b border-gray-800 py-12 hover:pl-8 transition-all',
        'skill_badge' => 'px-4 py-1 border border-gray-600 rounded-full mr-2 mb-2 inline-block text-sm',
        'nav_bg' => 'bg-black/90', 'btn_bg' => 'bg-white', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    // ─── NEW 20 TEMPLATES ───
    'gradient' => [
        'bg' => 'bg-[radial-gradient(circle_at_top_left,#4f46e5,#9333ea,#000000)]', 'text' => 'text-white', 'accent' => 'text-indigo-200', 'font' => 'Poppins',
        'container' => 'max-w-6xl mx-auto px-8 py-24',
        'heading' => 'text-7xl font-black mb-16 tracking-tight',
        'card' => 'bg-white/10 backdrop-blur-2xl p-10 rounded-3xl border border-white/20',
        'skill_badge' => 'px-5 py-2 bg-indigo-500/30 rounded-full text-sm mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-black/20', 'btn_bg' => 'bg-indigo-500', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'dark_minimal' => [
        'bg' => 'bg-[#0a0a0a]', 'text' => 'text-[#888]', 'accent' => 'text-white', 'font' => 'Inter',
        'container' => 'max-w-3xl mx-auto px-8 py-32',
        'heading' => 'text-sm font-bold uppercase tracking-[0.3em] mb-12 text-white',
        'card' => 'mb-16 border-l border-white/10 pl-8',
        'skill_badge' => 'text-xs font-mono mr-4 mb-2 inline-block',
        'nav_bg' => 'bg-black/80', 'btn_bg' => 'bg-white', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'magazine' => [
        'bg' => 'bg-[#f8f8f8]', 'text' => 'text-[#1a1a1a]', 'accent' => 'text-red-600', 'font' => 'Georgia',
        'container' => 'max-w-5xl mx-auto px-10 py-24 border-x border-black/5',
        'heading' => 'text-8xl font-serif italic mb-20 border-b-2 border-black pb-8',
        'card' => 'grid grid-cols-1 md:grid-cols-3 gap-8 mb-20 items-center',
        'skill_badge' => 'text-2xl font-serif italic mr-6 mb-4 inline-block',
        'nav_bg' => 'bg-white', 'btn_bg' => 'bg-black', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'game' => [
        'bg' => 'bg-[#36393f]', 'text' => 'text-[#dcddde]', 'accent' => 'text-[#7289da]', 'font' => 'Inter',
        'container' => 'max-w-5xl mx-auto px-8 py-20',
        'heading' => 'text-2xl font-bold mb-8 uppercase text-white flex items-center gap-4 before:h-1 before:flex-grow before:bg-[#40444b]',
        'card' => 'bg-[#2f3136] p-6 rounded-lg mb-4 hover:bg-[#32353b] transition-colors border border-black/20',
        'skill_badge' => 'px-3 py-1 bg-[#40444b] rounded text-xs mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-[#202225]', 'btn_bg' => 'bg-[#43b581]', 'btn_text' => 'text-white', 'layout' => 'sidebar'
    ],
    'terminal' => [
        'bg' => 'bg-[#0d0d0d]', 'text' => 'text-[#00ff00]', 'accent' => 'text-white', 'font' => 'Fira Code',
        'container' => 'max-w-4xl mx-auto px-8 py-12',
        'heading' => 'text-xl mb-8 before:content-[">_"]',
        'card' => 'border border-[#00ff00]/30 p-6 mb-8 hover:bg-[#00ff00]/5 transition-all',
        'skill_badge' => 'mr-4 mb-2 inline-block before:content-["["] after:content-["]"]',
        'nav_bg' => 'bg-black', 'btn_bg' => 'bg-[#00ff00]', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'glass' => [
        'bg' => 'bg-gradient-to-tr from-[#ff9a9e] 0%, #fecfef 99%, #fecfef 100%]', 'text' => 'text-[#4a4a4a]', 'accent' => 'text-white', 'font' => 'Poppins',
        'container' => 'max-w-6xl mx-auto px-8 py-24',
        'heading' => 'text-5xl font-bold mb-16 text-white drop-shadow-lg',
        'card' => 'bg-white/30 backdrop-blur-xl border border-white/40 p-8 rounded-[40px] shadow-2xl',
        'skill_badge' => 'px-4 py-2 bg-white/50 rounded-2xl mr-2 mb-2 inline-block text-sm',
        'nav_bg' => 'bg-white/20', 'btn_bg' => 'bg-white', 'btn_text' => 'text-[#ff9a9e]', 'layout' => 'standard'
    ],
    'aurora' => [
        'bg' => 'bg-slate-950', 'text' => 'text-slate-200', 'accent' => 'text-cyan-400', 'font' => 'Outfit',
        'container' => 'max-w-6xl mx-auto px-8 py-32',
        'heading' => 'text-6xl font-black mb-16 tracking-tighter bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600',
        'card' => 'bg-slate-900/50 backdrop-blur-3xl border border-slate-800 p-10 rounded-[2rem] shadow-[0_0_50px_-12px_rgba(34,211,238,0.1)]',
        'skill_badge' => 'px-4 py-1.5 bg-cyan-400/10 border border-cyan-400/20 rounded-full text-cyan-400 text-xs font-bold uppercase tracking-widest mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-slate-950/80', 'btn_bg' => 'bg-gradient-to-r from-cyan-500 to-blue-600', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'blueprint' => [
        'bg' => 'bg-[#1a3a5f] bg-[radial-gradient(#ffffff10_1px,transparent_1px)] [background-size:20px_20px]', 'text' => 'text-[#a0c4ff]', 'accent' => 'text-white', 'font' => 'Ubuntu Mono',
        'container' => 'max-w-5xl mx-auto px-10 py-20 border-x border-white/10',
        'heading' => 'text-4xl font-bold mb-12 uppercase tracking-[0.2em] border-b-2 border-white/20 pb-4',
        'card' => 'border border-white/20 p-8 relative before:absolute before:-top-2 before:-left-2 before:w-4 before:h-4 before:border-t-2 before:border-l-2 before:border-white/40 after:absolute after:-bottom-2 after:-right-2 after:w-4 after:h-4 after:border-b-2 after:border-r-2 after:border-white/40',
        'skill_badge' => 'px-3 py-1 border border-white/20 font-mono text-sm mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-[#1a3a5f]/95', 'btn_bg' => 'bg-white', 'btn_text' => 'text-[#1a3a5f]', 'layout' => 'standard'
    ],
    'vaporwave' => [
        'bg' => 'bg-[#120458] bg-[linear-gradient(transparent_0%,#ff71ce20_50%,transparent_100%)] [background-size:100%_4px]', 'text' => 'text-[#01cdfe]', 'accent' => 'text-[#fffb96]', 'font' => 'Montserrat',
        'container' => 'max-w-6xl mx-auto px-8 py-24',
        'heading' => 'text-8xl font-black mb-16 italic tracking-tighter text-transparent bg-clip-text bg-gradient-to-b from-[#ff71ce] to-[#01cdfe] drop-shadow-[0_5px_15px_rgba(255,113,206,0.5)]',
        'card' => 'bg-[#050505] border-2 border-[#ff71ce] p-8 shadow-[10px_10px_0_#05ffa1]',
        'skill_badge' => 'px-4 py-1 bg-[#b967ff] text-white font-black italic uppercase mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-[#120458]/90', 'btn_bg' => 'bg-[#05ffa1]', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'charcoal' => [
        'bg' => 'bg-[#0f0f0f]', 'text' => 'text-[#a1a1a1]', 'accent' => 'text-[#c5a059]', 'font' => 'Lora',
        'container' => 'max-w-4xl mx-auto px-12 py-32',
        'heading' => 'text-5xl font-serif mb-16 text-[#c5a059] border-b border-[#c5a059]/20 pb-8 text-center uppercase tracking-[0.3em]',
        'card' => 'bg-[#161616] p-12 border-l border-[#c5a059]/30 mb-12 hover:bg-[#1a1a1a] transition-all',
        'skill_badge' => 'text-xs uppercase tracking-widest text-[#c5a059] font-bold border border-[#c5a059]/20 px-3 py-1 mr-3 mb-3 inline-block',
        'nav_bg' => 'bg-[#0f0f0f]', 'btn_bg' => 'bg-[#c5a059]', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'parchment' => [
        'bg' => 'bg-[#f4ecd8]', 'text' => 'text-[#4a3728]', 'accent' => 'text-[#8b4513]', 'font' => 'Playfair Display',
        'container' => 'max-w-4xl mx-auto px-12 py-24 shadow-[0_0_50px_rgba(0,0,0,0.05)] bg-[#fdfaf1]',
        'heading' => 'text-5xl font-serif italic mb-16 border-b-2 double border-[#8b4513]/30 pb-6',
        'card' => 'border-b border-[#8b4513]/10 py-10 last:border-0',
        'skill_badge' => 'font-serif italic text-lg mr-6 mb-2 inline-block underline decoration-[#8b4513]/30',
        'nav_bg' => 'bg-[#f4ecd8]', 'btn_bg' => 'bg-[#4a3728]', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'comic' => [
        'bg' => 'bg-yellow-400 [background-image:radial-gradient(black_1px,transparent_0)] [background-size:20px_20px]', 'text' => 'text-black', 'accent' => 'text-red-600', 'font' => 'Bebas Neue',
        'container' => 'max-w-5xl mx-auto px-8 py-20',
        'heading' => 'text-9xl font-black mb-16 uppercase italic bg-white inline-block px-8 border-4 border-black shadow-[15px_15px_0_black] -rotate-2',
        'card' => 'bg-white border-4 border-black p-8 shadow-[10px_10px_0_black] hover:translate-x-1 hover:translate-y-1 transition-all mb-12',
        'skill_badge' => 'px-4 py-1 bg-cyan-400 border-2 border-black font-black uppercase tracking-tighter mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-white', 'btn_bg' => 'bg-red-600', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'minimal_white' => [
        'bg' => 'bg-[#fcfcfc]', 'text' => 'text-zinc-600', 'accent' => 'text-zinc-900', 'font' => 'Inter',
        'container' => 'max-w-3xl mx-auto px-8 py-40',
        'heading' => 'text-6xl font-black mb-20 text-zinc-900 tracking-tight',
        'card' => 'mb-24 group',
        'skill_badge' => 'text-sm font-medium text-zinc-400 mr-8 mb-2 inline-block group-hover:text-zinc-900 transition-colors',
        'nav_bg' => 'bg-white/50', 'btn_bg' => 'bg-zinc-900', 'btn_text' => 'text-white', 'layout' => 'standard'
    ],
    'techno' => [
        'bg' => 'bg-[#020617] [background-image:linear-gradient(#1e293b_1px,transparent_1px),linear-gradient(90deg,#1e293b_1px,transparent_1px)] [background-size:50px_50px]', 'text' => 'text-slate-400', 'accent' => 'text-sky-400', 'font' => 'Ubuntu Mono',
        'container' => 'max-w-7xl mx-auto px-6 py-20',
        'heading' => 'text-sm font-mono mb-12 text-sky-400 flex items-center gap-4 after:h-[1px] after:flex-grow after:bg-sky-400/30',
        'card' => 'bg-slate-900/80 border border-slate-800 p-8 relative overflow-hidden group',
        'skill_badge' => 'px-2 py-0.5 bg-sky-500/10 border border-sky-500/20 text-sky-400 text-xs mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-[#020617]/90', 'btn_bg' => 'bg-sky-500', 'btn_text' => 'text-white', 'layout' => 'grid'
    ],
    'retro_future' => [
        'bg' => 'bg-[#1a2f1a] bg-[radial-gradient(#2ecc7120_1px,transparent_1px)] [background-size:30px_30px]', 'text' => 'text-[#2ecc71]', 'accent' => 'text-[#f1c40f]', 'font' => 'Fira Code',
        'container' => 'max-w-5xl mx-auto px-8 py-20 border-4 border-[#2ecc71]/30 rounded-[3rem]',
        'heading' => 'text-4xl font-bold mb-12 uppercase tracking-widest text-[#f1c40f] drop-shadow-[0_0_10px_rgba(241,196,15,0.5)]',
        'card' => 'bg-black/40 border-2 border-[#2ecc71]/40 p-8 rounded-3xl shadow-[inset_0_0_20px_rgba(46,204,113,0.1)]',
        'skill_badge' => 'px-3 py-1 bg-[#2ecc71] text-[#1a2f1a] font-bold mr-2 mb-2 inline-block rounded',
        'nav_bg' => 'bg-[#1a2f1a]/95', 'btn_bg' => 'bg-[#f1c40f]', 'btn_text' => 'text-black', 'layout' => 'standard'
    ],
    'nordic' => [
        'bg' => 'bg-[#f1f5f9]', 'text' => 'text-[#475569]', 'accent' => 'text-[#0f172a]', 'font' => 'Montserrat',
        'container' => 'max-w-6xl mx-auto px-12 py-32',
        'heading' => 'text-4xl font-light mb-16 text-[#0f172a] uppercase tracking-[0.5em] border-l-8 border-[#0f172a] pl-8',
        'card' => 'bg-white p-12 shadow-[0_4px_20px_rgba(0,0,0,0.03)] border-t-4 border-[#0f172a]',
        'skill_badge' => 'px-5 py-2 border border-slate-200 text-slate-500 text-xs uppercase tracking-widest mr-2 mb-2 inline-block',
        'nav_bg' => 'bg-white', 'btn_bg' => 'bg-[#0f172a]', 'btn_text' => 'text-white', 'layout' => 'standard'
    ]
];

// Clones and variations to reach 39
$base_variations = [
    'creator' => ['base' => 'modern', 'bg' => 'bg-rose-950', 'accent' => 'text-rose-400', 'nav_bg' => 'bg-rose-950/80', 'btn_bg' => 'bg-rose-400', 'btn_text' => 'text-rose-950'],
    'professional' => ['base' => 'corporate', 'bg' => 'bg-white', 'accent' => 'text-emerald-700', 'nav_bg' => 'bg-white', 'btn_bg' => 'bg-emerald-700', 'btn_text' => 'text-white'],
    'playful' => ['base' => 'neobrutalism', 'bg' => 'bg-[#fbcfe8]', 'accent' => 'text-[#be185d]', 'nav_bg' => 'bg-[#fbcfe8]', 'btn_bg' => 'bg-[#be185d]', 'btn_text' => 'text-white'],
    'monochrome' => ['base' => 'minimal', 'bg' => 'bg-zinc-950', 'text' => 'text-zinc-300', 'card' => 'bg-zinc-900 p-8', 'nav_bg' => 'bg-zinc-950/80', 'btn_bg' => 'bg-white', 'btn_text' => 'text-black'],
    'editorial' => ['base' => 'magazine', 'bg' => 'bg-[#f4f0eb]', 'font' => 'Georgia', 'heading' => 'text-5xl italic border-b border-black mb-12', 'nav_bg' => 'bg-[#f4f0eb]'],
    'futuristic' => ['base' => 'cyberpunk', 'bg' => 'bg-[#0f172a]', 'accent' => 'text-[#38bdf8]', 'nav_bg' => 'bg-[#0f172a]/80', 'btn_bg' => 'bg-[#38bdf8]', 'btn_text' => 'text-black'],
    'nature' => ['base' => 'bento', 'bg' => 'bg-[#f3f4f1]', 'accent' => 'text-[#4d7c0f]', 'nav_bg' => 'bg-[#f3f4f1]/80', 'btn_bg' => 'bg-[#4d7c0f]', 'btn_text' => 'text-white'],
    'geometric' => ['base' => 'minimal', 'bg' => 'bg-white', 'card' => 'border-2 border-black p-8 rounded-none', 'nav_bg' => 'bg-white', 'btn_bg' => 'bg-black', 'btn_text' => 'text-white'],
    'typographic' => ['base' => 'creative', 'bg' => 'bg-yellow-400', 'text' => 'text-black', 'nav_bg' => 'bg-yellow-400', 'btn_bg' => 'bg-black', 'btn_text' => 'text-white'],
    
    // ─── SECOND WAVE VARIATIONS ───
    'glitch' => ['base' => 'cyberpunk', 'bg' => 'bg-black', 'accent' => 'text-red-500', 'heading' => 'text-5xl font-black italic skew-x-[-10deg]'],
    'brutalist' => ['base' => 'neobrutalism', 'bg' => 'bg-gray-300', 'card' => 'bg-gray-200 border-2 border-black rounded-none shadow-none'],
    'pastel' => ['base' => 'glass', 'bg' => 'bg-blue-50', 'text' => 'text-blue-900', 'card' => 'bg-white rounded-[60px] border-none shadow-sm'],
    'sketch' => ['base' => 'minimal', 'bg' => 'bg-[#fdf6e3]', 'font' => 'Comic Sans MS', 'card' => 'border-2 border-dashed border-gray-400 p-8'],
    'architect' => ['base' => 'corporate', 'bg' => 'bg-gray-100', 'font' => 'Inter', 'heading' => 'text-sm font-bold tracking-[0.5em] text-gray-400 uppercase mb-8'],
    'vogue' => ['base' => 'magazine', 'bg' => 'bg-white', 'text' => 'text-black', 'heading' => 'text-[120px] font-serif uppercase tracking-tighter leading-none mb-24'],
    'hacker' => ['base' => 'terminal', 'bg' => 'bg-black', 'text' => 'text-[#00ff41]', 'heading' => 'text-2xl font-mono border-b border-[#00ff41] pb-2'],
    'neon' => ['base' => 'modern', 'bg' => 'bg-black', 'accent' => 'text-yellow-400', 'card' => 'bg-black border border-yellow-400/50 shadow-[0_0_20px_rgba(250,204,21,0.2)]'],
    'material' => ['base' => 'corporate', 'bg' => 'bg-[#fafafa]', 'card' => 'bg-white rounded shadow-md border-none'],
    'organic' => ['base' => 'bento', 'bg' => 'bg-[#f8f9fa]', 'card' => 'bg-emerald-50 rounded-[100px] border-none'],
    'pop_art' => ['base' => 'creative', 'bg' => 'bg-cyan-400', 'card' => 'bg-white border-4 border-black p-8 shadow-[12px_12px_0_#000]'],
    'industrial' => ['base' => 'developer', 'bg' => 'bg-[#2b2b2b]', 'text' => 'text-gray-400', 'accent' => 'text-orange-500'],
    'zen' => ['base' => 'minimal', 'bg' => 'bg-white', 'text' => 'text-stone-400', 'accent' => 'text-stone-900', 'container' => 'max-w-2xl mx-auto py-40'],
    'software' => ['base' => 'corporate', 'bg' => 'bg-white', 'accent' => 'text-blue-600', 'card' => 'bg-blue-50 border-none p-10 rounded-3xl'],

    // ─── NEW 20 PREMIUM TEMPLATES (from seed_new_templates.php) ───
    'neon_noir' => ['base' => 'cyberpunk', 'bg' => 'bg-black', 'accent' => 'text-yellow-400', 'nav_bg' => 'bg-black/90'],
    'watercolor' => ['base' => 'minimal', 'bg' => 'bg-[#fef9f3]', 'text' => 'text-[#5d4037]', 'font' => 'Playfair Display'],
    'glass_lux' => ['base' => 'glass', 'bg' => 'bg-gradient-to-br from-black to-neutral-900', 'accent' => 'text-yellow-500'],
    'graffiti' => ['base' => 'creative', 'bg' => 'bg-neutral-900', 'text' => 'text-white', 'accent' => 'text-yellow-400'],
    'editorial_mag' => ['base' => 'magazine', 'bg' => 'bg-white', 'font' => 'Inter'],
    'corporate_edge' => ['base' => 'corporate', 'bg' => 'bg-slate-50', 'accent' => 'text-indigo-600'],
    'finance_pro' => ['base' => 'corporate', 'bg' => 'bg-white', 'accent' => 'text-blue-900'],
    'legal_classic' => ['base' => 'charcoal', 'bg' => 'bg-[#1a1a1a]', 'accent' => 'text-[#c5a059]'],
    'startup_pitch' => ['base' => 'modern', 'bg' => 'bg-white', 'text' => 'text-slate-900', 'accent' => 'text-indigo-600'],
    'consulting_clean' => ['base' => 'minimal', 'bg' => 'bg-white', 'text' => 'text-slate-800'],
    'terminal_portfolio' => ['base' => 'terminal', 'bg' => 'bg-black', 'text' => 'text-green-500'],
    'code_grid' => ['base' => 'developer', 'bg' => 'bg-[#0a0a0a]', 'accent' => 'text-blue-400'],
    'ai_matrix' => ['base' => 'terminal', 'bg' => 'bg-black', 'text' => 'text-emerald-500'],
    'blockchain_dark' => ['base' => 'aurora', 'bg' => 'bg-black', 'accent' => 'text-cyan-400'],
    'pixel_arcade' => ['base' => 'retro', 'bg' => 'bg-black', 'text' => 'text-purple-400'],
    'gaming_hud' => ['base' => 'techno', 'bg' => 'bg-black', 'accent' => 'text-red-500'],
    'meme_pop' => ['base' => 'creative', 'bg' => 'bg-yellow-300', 'text' => 'text-black'],
    'storybook' => ['base' => 'parchment', 'bg' => 'bg-[#fdf6e3]', 'text' => 'text-[#586e75]'],
    'zen_japanese' => ['base' => 'nordic', 'bg' => 'bg-white', 'text' => 'text-stone-800'],
    'desert_royal' => ['base' => 'charcoal', 'bg' => 'bg-[#2d1b0d]', 'accent' => 'text-[#d4af37]']
];

foreach ($base_variations as $slug => $mods) {
    if (!isset($configs[$slug])) {
        $configs[$slug] = $configs[$mods['base']];
        foreach ($mods as $k => $v) {
            if ($k !== 'base') $configs[$slug][$k] = $v;
        }
    }
}

foreach ($configs as $slug => $c) {
    $php = '<?php // Auto-generated Full Data Template: ' . ucfirst($slug) . ' ?>
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
        body { font-family: "' . $c['font'] . '", sans-serif; }
        section { scroll-margin-top: 100px; }
        .nav-link { position: relative; transition: opacity 0.3s; }
        .nav-link::after { content: ""; position: absolute; bottom: -4px; left: 0; width: 0; height: 2px; background: currentColor; transition: width 0.3s; }
        .nav-link:hover::after { width: 100%; }
        .fade-in { animation: fadeIn 1s ease-out forwards; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body class="' . $c['bg'] . ' ' . $c['text'] . ' antialiased selection:bg-yellow-400 selection:text-black">

<!-- NAVIGATION BAR -->
<nav class="fixed top-0 left-0 right-0 z-50 ' . $c['nav_bg'] . ' backdrop-blur-md border-b border-current/10 py-4">
    <div class="max-w-7xl mx-auto px-6 flex justify-between items-center">
        <div class="font-bold text-xl tracking-tighter cursor-pointer" onclick="window.scrollTo({top:0, behavior:\'smooth\'})"><?= htmlspecialchars($d["name"]) ?></div>
        <div class="hidden md:flex gap-8 text-sm font-medium uppercase tracking-widest opacity-70">
            <a href="#about" class="nav-link">About</a>
            <a href="#experience" class="nav-link">Experience</a>
            <a href="#projects" class="nav-link">Projects</a>
            <a href="#skills" class="nav-link">Skills</a>
            <a href="#certificates" class="nav-link">Certificates</a>
            <a href="#achievements" class="nav-link">Awards</a>
        </div>
        <a href="mailto:<?= htmlspecialchars($d["email"]) ?>" class="' . $c['btn_bg'] . ' ' . $c['btn_text'] . ' px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-tighter hover:opacity-80 transition-opacity">Hire Me</a>
    </div>
</nav>

<div class="' . $c['container'] . ' pt-32">

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
            <h2 class="text-3xl md:text-4xl ' . $c['accent'] . ' mb-6"><?= htmlspecialchars($d["job_title"]) ?></h2>
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
        <h3 class="' . $c['heading'] . '">About Me</h3>
        <div class="text-xl leading-relaxed opacity-90 max-w-4xl">
            <?= nl2br(htmlspecialchars($d["bio"])) ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- EXPERIENCE SECTION -->
    <?php if(!empty($d["experience"]) && ($d["sections"]["experience"] ?? true)): ?>
    <section id="experience" class="mb-24 fade-in" style="animation-delay:0.4s">
        <h3 class="' . $c['heading'] . '">Experience</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
            <?php foreach($d["experience"] as $exp): ?>
            <div class="' . $c['card'] . ' group">
                <div class="flex justify-between items-start mb-4">
                    <h4 class="text-2xl font-bold group-hover:' . $c['accent'] . ' transition-colors"><?= htmlspecialchars($exp["title"]) ?></h4>
                    <span class="text-sm font-bold opacity-70 bg-current/10 px-3 py-1 rounded"><?= htmlspecialchars($exp["period"]) ?></span>
                </div>
                <h5 class="text-lg ' . $c['accent'] . ' mb-4"><?= htmlspecialchars($exp["company"]) ?></h5>
                <p class="opacity-80 leading-relaxed"><?= htmlspecialchars($exp["description"]) ?></p>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- PROJECTS SECTION -->
    <?php if(!empty($d["projects"]) && ($d["sections"]["projects"] ?? true)): ?>
    <section id="projects" class="mb-24 fade-in" style="animation-delay:0.6s">
        <h3 class="' . $c['heading'] . '">Projects</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            <?php foreach($d["projects"] as $proj): ?>
            <div class="' . $c['card'] . ' flex flex-col h-full group">
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
        <h3 class="' . $c['heading'] . '">Skills & Technologies</h3>
        <div class="flex flex-wrap gap-4">
            <?php foreach($d["skills"] as $skill): ?>
            <span class="' . $c['skill_badge'] . ' hover:scale-110 transition-transform"><?= htmlspecialchars($skill) ?></span>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- CERTIFICATES SECTION -->
    <?php if(!empty($d["certificates"]) && ($d["sections"]["certifications"] ?? true)): ?>
    <section id="certificates" class="mb-24 fade-in" style="animation-delay:1s">
        <h3 class="' . $c['heading'] . '">Certifications</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <?php foreach($d["certificates"] as $cert): ?>
            <div class="' . $c['card'] . '">
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
        <h3 class="' . $c['heading'] . '">Achievements & Awards</h3>
        <div class="grid grid-cols-1 gap-4">
            <?php foreach($d["achievements"] as $ach): ?>
            <div class="flex items-start gap-4 p-6 border-l-4 border-current bg-current/5">
                <i class="fas fa-trophy mt-1 ' . $c['accent'] . '"></i>
                <span class="text-lg opacity-90"><?= htmlspecialchars($ach) ?></span>
            </div>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- GET IN TOUCH SECTION -->
    <?php if($d["sections"]["contact"] ?? true): ?>
    <section id="contact" class="mb-24 fade-in text-center" style="animation-delay:1.2s">
        <h3 class="' . $c['heading'] . '">Get In Touch</h3>
        <p class="text-xl opacity-70 mb-10 max-w-2xl mx-auto">Have a project in mind or just want to say hi? I\'d love to hear from you!</p>
        <div class="flex flex-wrap justify-center gap-8">
            <a href="mailto:<?= htmlspecialchars($d["email"]) ?>" class="' . $c['btn_bg'] . ' ' . $c['btn_text'] . ' px-10 py-5 rounded-full text-lg font-bold uppercase tracking-widest hover:scale-105 transition-transform inline-flex items-center gap-3">
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
    <button onclick="sharePortfolio()" class="' . $c['btn_bg'] . ' ' . $c['btn_text'] . ' w-16 h-16 rounded-full shadow-2xl flex items-center justify-center hover:scale-110 active:scale-95 transition-all group" title="Share Portfolio">
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
';
    file_put_contents($viewsDir . '/' . $slug . '.php', $php);
}

echo "Successfully generated 69 distinct rich templates (Total 70 with Cinematic)!";
?>
