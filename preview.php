<?php
require_once 'api/config.php';
header('Content-Type: text/html; charset=utf-8');

$id = intval($_GET['id'] ?? 0);
$slug = $_GET['slug'] ?? '';
$templateSlug = $_GET['template'] ?? '';

$d = [];
$found = false;

if ($id || $slug) {
    $where = $id ? "p.id = $id" : "p.slug = '$slug'";
    $res = $conn->query("
        SELECT p.*, t.slug as template_slug 
        FROM portfolios p 
        LEFT JOIN templates t ON p.template_id = t.id 
        WHERE $where
    ");
    if ($res && $res->num_rows > 0) {
        $p = $res->fetch_assoc();
        $content = json_decode($p['content_json'], true);
        $sections = json_decode($p['sections_visibility'], true);
        
        $d = [
            'name' => $content['name'] ?? 'Portfolio Owner',
            'job_title' => $p['role_type'] ?? '',
            'bio' => $content['about'] ?? '',
            'location' => $content['contact']['location'] ?? '',
            'email' => $content['contact']['email'] ?? '',
            'website' => $content['contact']['website'] ?? '',
            'phone' => $content['contact']['phone'] ?? '',
            'avatar' => $p['avatar'] ?? 'avatar-placeholder', // SVG avatars embedded in templates
            'score' => $p['score'] ?? 85,
            'skills' => $content['skills'] ?? [],
            'projects' => $content['projects'] ?? [],
            'experience' => $content['experience'] ?? [],
            'certificates' => $content['certificates'] ?? [],
            'achievements' => $content['achievements'] ?? [],
            'sections' => $sections ?: ['about'=>true, 'skills'=>true, 'projects'=>true, 'experience'=>true, 'contact'=>true]
        ];
        
        if (!$templateSlug) $templateSlug = $p['template_slug'];
        $found = true;
    }
}

if (!$found) {
    // Fallback to High-Quality Mock Data (Demo)
    $d = [
        'name' => 'Alex Rivera',
        'job_title' => 'Senior Digital Designer & Developer',
        'bio' => "I build digital experiences that live at the intersection of design and engineering. With over a decade of experience creating scalable, beautiful, and accessible web applications, I help brands tell their stories through code and pixels.",
        'location' => 'San Francisco, CA',
        'email' => 'hello@alexrivera.dev',
        'website' => 'https://alexrivera.dev',
        'phone' => '+1 (555) 123-4567',
        'avatar' => 'avatar-placeholder', // SVG avatars embedded in templates
        'score' => 98,
        'skills' => ['React', 'Node.js', 'Three.js', 'Figma', 'TypeScript', 'TailwindCSS', 'GraphQL', 'Next.js'],
        'projects' => [
            ['title' => 'Nexus Financial Dashboard', 'description' => 'A high-performance fintech dashboard handling real-time socket data streams.', 'tech' => ['React', 'TypeScript', 'D3.js'], 'link' => '#'],
            ['title' => 'Aura eCommerce Platform', 'description' => 'Headless Shopify implementation with massive performance gains.', 'tech' => ['Next.js', 'Three.js', 'Shopify'], 'link' => '#']
        ],
        'experience' => [
            ['title' => 'Lead Frontend Engineer', 'company' => 'Vercel Labs', 'period' => '2022 - Present', 'description' => 'Spearheaded the migration to the new App Router architecture.'],
            ['title' => 'Senior UI Designer', 'company' => 'Stripe', 'period' => '2019 - 2022', 'description' => 'Designed the next-generation checkout experience.']
        ],
        'certificates' => [
            ['name' => 'AWS Certified Solutions Architect', 'issuer' => 'Amazon Web Services', 'date' => '2023'],
            ['name' => 'Google UX Design Professional', 'issuer' => 'Google', 'date' => '2022']
        ],
        'achievements' => [
            'Awwwards Site of the Day (2023)',
            'Featured in Smashing Magazine for CSS Architecture'
        ],
        'social' => [
            ['platform' => 'github', 'url' => 'https://github.com'],
            ['platform' => 'linkedin', 'url' => 'https://linkedin.com']
        ],
        'sections' => [
            'about' => true, 'skills' => true, 'projects' => true, 'experience' => true, 
            'certifications' => true, 'achievements' => true, 'contact' => true
        ]
    ];
    if (!$templateSlug) $templateSlug = 'cinematic';
}

$viewFile = __DIR__ . '/portfolio/views/' . $templateSlug . '.php';
if (!file_exists($viewFile)) {
    die("<h1>Template preview not available yet.</h1>");
}

$assetsPath = '';

// Provide helper functions that view files normally expect
if (!function_exists('splitChars')) {
    function splitChars($text) {
        $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
        $out = '';
        foreach ($chars as $c) {
            $class = $c === ' ' ? 'char inline-block w-4' : 'char inline-block';
            $out .= '<span class="' . $class . '">' . htmlspecialchars($c === ' ' ? "\u{00A0}" : $c) . '</span>';
        }
        return $out;
    }
}

include $viewFile;
?>
