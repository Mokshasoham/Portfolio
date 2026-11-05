<?php
/**
 * Shared renderer for the Feature Showcase collection.
 * The selected template changes the palette, headline, and presentation pattern.
 */
$variants = [
    'data_story' => [
        'eyebrow' => 'Data Story / 01', 'name' => 'Data Story', 'accent' => '#64f5c5', 'accent2' => '#569dff',
        'tagline' => 'A portfolio that turns outcomes into a clear, visual narrative.',
        'feature' => 'Impact dashboard', 'detail' => 'Outcome metrics, project signals, and a scrollable delivery timeline make results easy to scan.'
    ],
    'product_launch' => [
        'eyebrow' => 'Product Launch / 01', 'name' => 'Product Launch', 'accent' => '#ffb454', 'accent2' => '#ff5d8f',
        'tagline' => 'A conversion-ready case-study format for people who ship products.',
        'feature' => 'Case-study runway', 'detail' => 'A bold product brief, release milestones, and proof points lead visitors from problem to outcome.'
    ],
    'studio_mosaic' => [
        'eyebrow' => 'Studio Mosaic / 01', 'name' => 'Studio Mosaic', 'accent' => '#dc9cff', 'accent2' => '#7e84ff',
        'tagline' => 'A curated, editorial canvas for multidisciplinary creative work.',
        'feature' => 'Editorial mosaic', 'detail' => 'A responsive project mosaic and selected-work index give art direction a gallery-like presence.'
    ],
];
$v = $variants[$templateSlug] ?? $variants['data_story'];
$projects = array_values(array_filter((array)($d['projects'] ?? []), fn($p) => is_array($p)));
$skills = array_slice(array_values(array_filter((array)($d['skills'] ?? []))), 0, 8);
$experience = array_slice(array_values(array_filter((array)($d['experience'] ?? []), fn($e) => is_array($e))), 0, 4);
?>
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= htmlspecialchars($d['name'] ?? 'Portfolio') ?> — <?= htmlspecialchars($v['name']) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--a:<?= $v['accent'] ?>;--b:<?= $v['accent2'] ?>;--ink:#101116;--paper:#f4f3ed;--muted:#696b73}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Manrope,Arial,sans-serif}.wrap{max-width:1180px;margin:auto;padding:28px}.nav{display:flex;justify-content:space-between;align-items:center;font:12px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.08em}.dot{width:12px;height:12px;border-radius:50%;background:var(--a);box-shadow:18px 0 var(--b)}.hero{padding:100px 0 70px;display:grid;grid-template-columns:1.45fr .55fr;gap:30px;border-bottom:1px solid #d2d2cc}.eyebrow,.label{font:12px 'DM Mono',monospace;color:var(--muted);letter-spacing:.1em;text-transform:uppercase}.hero h1{font-size:clamp(54px,9vw,126px);line-height:.88;letter-spacing:-.08em;margin:15px 0 24px}.hero p{max-width:590px;font-size:20px;line-height:1.55}.hero-card{align-self:end;padding:24px;background:var(--ink);color:white;border-radius:20px}.hero-card strong{color:var(--a);display:block;font-size:34px;letter-spacing:-.06em;margin:12px 0}.section{padding:72px 0;border-bottom:1px solid #d2d2cc}.section-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:32px}.section h2{font-size:28px;letter-spacing:-.05em;margin:0}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.metric{padding:24px;border:1px solid #d2d2cc;border-radius:16px;background:white}.metric b{font-size:38px;letter-spacing:-.07em;display:block;color:var(--b)}.mosaic{display:grid;grid-template-columns:repeat(12,1fr);gap:16px}.project{grid-column:span 5;min-height:230px;padding:25px;border-radius:18px;background:linear-gradient(135deg,var(--ink),#313541);color:white;display:flex;flex-direction:column;justify-content:end}.project:nth-child(3n+2){grid-column:span 7;background:linear-gradient(135deg,var(--a),var(--b));color:var(--ink)}.project:nth-child(3n){grid-column:span 7;background:#deddd5;color:var(--ink)}.project h3{font-size:26px;letter-spacing:-.05em;margin:8px 0}.project p{max-width:520px;margin:0;opacity:.78}.tags{display:flex;gap:8px;flex-wrap:wrap}.tag{font:12px 'DM Mono',monospace;padding:7px 10px;border-radius:99px;background:white;border:1px solid #d2d2cc}.timeline{display:grid;gap:0}.event{display:grid;grid-template-columns:170px 1fr;gap:20px;padding:21px 0;border-top:1px solid #d2d2cc}.event h3{margin:0;font-size:17px}.event p{margin:7px 0 0;color:var(--muted)}.contact{padding:85px 0;text-align:center}.contact h2{font-size:clamp(42px,7vw,82px);line-height:.95;letter-spacing:-.07em;margin:14px 0 30px}.button{display:inline-block;text-decoration:none;background:var(--ink);color:white;padding:15px 23px;border-radius:99px;font-weight:700}@media(max-width:700px){.hero{grid-template-columns:1fr;padding-top:70px}.metrics{grid-template-columns:1fr}.project,.project:nth-child(3n+2),.project:nth-child(3n){grid-column:span 12}.event{grid-template-columns:1fr;gap:6px}}
</style></head><body><main class="wrap"><nav class="nav"><span class="dot"></span><span><?= htmlspecialchars($v['name']) ?></span><span><?= htmlspecialchars($d['name'] ?? 'Portfolio') ?></span></nav>
<section class="hero"><div><div class="eyebrow"><?= htmlspecialchars($v['eyebrow']) ?></div><h1><?= htmlspecialchars($d['name'] ?? 'Portfolio Owner') ?></h1><p><?= htmlspecialchars($d['bio'] ?? $v['tagline']) ?></p></div><aside class="hero-card"><span class="label">Signature feature</span><strong><?= htmlspecialchars($v['feature']) ?></strong><span><?= htmlspecialchars($v['detail']) ?></span></aside></section>
<section class="section"><div class="section-head"><h2>Signal overview</h2><span class="label">Built for skimming</span></div><div class="metrics"><div class="metric"><span class="label">Portfolio score</span><b><?= htmlspecialchars((string)($d['score'] ?? '—')) ?></b><span>Craft and completeness</span></div><div class="metric"><span class="label">Selected work</span><b><?= count($projects) ?></b><span>Documented projects</span></div><div class="metric"><span class="label">Core tools</span><b><?= count($skills) ?></b><span>Skills in focus</span></div></div></section>
<section class="section"><div class="section-head"><h2>Selected work</h2><span class="label">Mosaic case studies</span></div><div class="mosaic"><?php foreach ($projects ?: [['title'=>'Your next case study','description'=>'Add a project from the editor to populate this showcase.']] as $p): ?><article class="project"><span class="label">Case study</span><h3><?= htmlspecialchars($p['title'] ?? 'Untitled project') ?></h3><p><?= htmlspecialchars($p['description'] ?? '') ?></p></article><?php endforeach; ?></div></section>
<section class="section"><div class="section-head"><h2>Capabilities</h2><span class="label">Working toolkit</span></div><div class="tags"><?php foreach ($skills ?: ['Strategy','Design','Delivery'] as $skill): ?><span class="tag"><?= htmlspecialchars(is_scalar($skill) ? (string)$skill : 'Skill') ?></span><?php endforeach; ?></div></section>
<?php if ($experience): ?><section class="section"><div class="section-head"><h2>Delivery timeline</h2><span class="label">Experience</span></div><div class="timeline"><?php foreach ($experience as $e): ?><article class="event"><span class="label"><?= htmlspecialchars($e['period'] ?? $e['duration'] ?? 'Timeline') ?></span><div><h3><?= htmlspecialchars($e['title'] ?? $e['role'] ?? 'Role') ?> · <?= htmlspecialchars($e['company'] ?? '') ?></h3><p><?= htmlspecialchars($e['description'] ?? '') ?></p></div></article><?php endforeach; ?></div></section><?php endif; ?>
<section class="contact"><span class="label">Available for thoughtful work</span><h2>Let’s make the next<br>story worth telling.</h2><?php if (!empty($d['email'])): ?><a class="button" href="mailto:<?= htmlspecialchars($d['email']) ?>">Start a conversation</a><?php endif; ?></section></main></body></html>
