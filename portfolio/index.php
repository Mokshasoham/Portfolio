<?php
/**
 * CreativePort — Cinematic Portfolio Viewer v3
 * Full cinematic intro, particle canvas, 3D cursor, GSAP reveals
 */
session_start();
header('Content-Type: text/html; charset=utf-8');
$conn = new mysqli('127.0.0.1', 'root', '', 'portfolio_db', 3307);
if ($conn->connect_error) die('<h1>Service Unavailable</h1>');
$conn->set_charset('utf8mb4');

$slug = trim($_GET['slug'] ?? '');
if ($slug === '') {
    $path = trim(parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH), '/');
    $segments = explode('/', $path);
    $portfolioIndex = array_search('portfolio', $segments, true);
    if ($portfolioIndex !== false && !empty($segments[$portfolioIndex + 1]) && $segments[$portfolioIndex + 1] !== 'index.php') {
        $slug = urldecode($segments[$portfolioIndex + 1]);
    }
}
if (empty($slug)) show404('No portfolio specified.');

$stmt = $conn->prepare("
    SELECT p.*, t.name as template_name, t.slug as template_slug,
           u.name as author_name, u.email as author_email, u.avatar as author_avatar,
           u.bio as author_bio, u.phone as author_phone, u.location as author_location,
           u.website as author_website, u.job_title as author_job_title,
           u.skills_json as author_skills, u.social_links_json as author_social
    FROM portfolios p
    JOIN users u ON p.user_id = u.id
    LEFT JOIN templates t ON p.template_id = t.id
    WHERE p.slug = ? AND p.status = 'published' AND p.is_public = 1
");
$stmt->bind_param("s", $slug);
$stmt->execute();
$portfolio = $stmt->get_result()->fetch_assoc();
$stmt->close();
if (!$portfolio) show404('This portfolio does not exist or is not published.');

// Track view
$isOwner = isset($_SESSION['user_id']) && $_SESSION['user_id'] == $portfolio['user_id'];
if (!$isOwner) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $stmt = $conn->prepare("INSERT INTO portfolio_views (portfolio_id, viewer_ip) VALUES (?, ?)");
    $stmt->bind_param("is", $portfolio['id'], $ip);
    $stmt->execute();
    $stmt->close();
}

$content = $portfolio['content_json'] ? json_decode($portfolio['content_json'], true) : [];
$sections = $portfolio['sections_visibility'] ? json_decode($portfolio['sections_visibility'], true) : [];
$authorSkills = $portfolio['author_skills'] ? json_decode($portfolio['author_skills'], true) : [];
$authorSocial = $portfolio['author_social'] ? json_decode($portfolio['author_social'], true) : [];

$experience = $content['experience'] ?? [];
foreach ($experience as &$exp) {
    $exp['title'] = $exp['title'] ?? $exp['role'] ?? '';
    $exp['role'] = $exp['role'] ?? $exp['title'];
    $exp['period'] = $exp['period'] ?? $exp['duration'] ?? '';
    $exp['duration'] = $exp['duration'] ?? $exp['period'];
    $exp['company'] = $exp['company'] ?? '';
    $exp['description'] = $exp['description'] ?? '';
}
unset($exp);

$projects = $content['projects'] ?? [];
foreach ($projects as &$project) {
    $project['title'] = $project['title'] ?? '';
    $project['description'] = $project['description'] ?? '';
    $project['tech'] = $project['tech'] ?? $project['tech_stack'] ?? '';
    $project['tech_stack'] = $project['tech_stack'] ?? (is_array($project['tech']) ? $project['tech'] : array_filter(array_map('trim', explode(',', $project['tech']))));
    $project['link'] = $project['link'] ?? $project['live_link'] ?? $project['github_link'] ?? '';
}
unset($project);

$certificates = $content['certificates'] ?? $content['certifications'] ?? [];
$certificates = normalizeCertificatesForView($certificates);
$achievements = normalizeTextListForView($content['achievements'] ?? []);
$education = normalizeEducationForView($content['education'] ?? []);
$additionalSections = is_array($content['additional_sections'] ?? null) ? $content['additional_sections'] : [];
$resumeProfile = is_array($content['resume_profile'] ?? null) ? $content['resume_profile'] : [];

// The canonical resume profile is template-independent. Preserve every
// populated section even when an older template has no dedicated layout.
foreach (['internships','hackathons','training','publications','volunteerExperience','leadership','languages','interests'] as $sectionName) {
    if (!empty($resumeProfile[$sectionName]) && empty($additionalSections[$sectionName])) {
        $additionalSections[$sectionName] = array_map(function ($item) {
            return is_array($item) ? ($item['text'] ?? implode(' - ', array_filter($item, 'is_scalar'))) : $item;
        }, (array)$resumeProfile[$sectionName]);
    }
}

foreach ($education as $edu) {
    $achievements[] = 'Education: ' . implode(' - ', array_filter([$edu['degree'], $edu['institution'], $edu['period']]));
}
foreach ($additionalSections as $label => $items) {
    foreach (normalizeTextListForView($items) as $item) {
        $achievements[] = ucfirst((string)$label) . ': ' . $item;
    }
}
$achievements = array_values(array_unique(array_filter($achievements)));
$socialLinks = $content['social_links'] ?? $content['social'] ?? $authorSocial;
$socialLinks = normalizeSocialForView($socialLinks);

$d = [
    'name' => !empty($content['name']) ? $content['name'] : $portfolio['author_name'],
    'email' => $content['contact']['email'] ?? $content['email'] ?? $portfolio['author_email'],
    'avatar' => $content['avatar'] ?? $portfolio['author_avatar'],
    'bio' => $content['about'] ?? $portfolio['author_bio'] ?? '',
    'job_title' => $portfolio['role_type'] ?: ($content['target_role'] ?? $content['job_title'] ?? $portfolio['author_job_title'] ?? ''),
    'location' => $content['contact']['location'] ?? $content['location'] ?? $portfolio['author_location'] ?? '',
    'website' => $content['website'] ?? $portfolio['author_website'] ?? '',
    'phone' => $content['contact']['phone'] ?? $content['phone'] ?? $portfolio['author_phone'] ?? '',
    'skills' => $content['skills'] ?? $authorSkills,
    'social' => $socialLinks,
    'projects' => $projects,
    'experience' => $experience,
    'certificates' => $certificates,
    'certifications' => $certificates,
    'achievements' => $achievements,
    'education' => $education,
    'additional_sections' => $additionalSections,
    'sections' => $sections,
    'score' => $portfolio['score']
];
$conn->close();

$assetsPath = '../';
$templateSlug = $portfolio['template_slug'] ?: 'cinematic';
$viewFile = __DIR__ . '/views/' . $templateSlug . '.php';

if (!file_exists($viewFile)) {
    $viewFile = __DIR__ . '/views/cinematic.php';
}

if (!file_exists($viewFile)) {
    show404('Template view not found.');
}

include $viewFile;

function show404($msg = 'Portfolio not found.') {
    http_response_code(404);
    echo '<!DOCTYPE html><html><head><title>404</title><script src="https://cdn.tailwindcss.com"></script></head>';
    echo '<body class="min-h-screen flex items-center justify-center bg-black text-white"><div class="text-center">';
    echo '<h1 class="text-6xl font-bold mb-4">404</h1><p class="text-xl text-zinc-500 mb-8">' . htmlspecialchars($msg) . '</p>';
    echo '<a href="../index.html" class="px-6 py-3 bg-white text-black rounded-full font-bold">Go Home</a></div></body></html>';
    exit;
}

function normalizeCertificatesForView($items) {
    $out = [];
    foreach ((array)$items as $item) {
        if (is_string($item)) {
            $out[] = ['name' => $item, 'issuer' => '', 'date' => ''];
        } elseif (is_array($item)) {
            $out[] = [
                'name' => trim($item['name'] ?? $item['title'] ?? implode(' - ', array_filter(array_map('strval', $item)))),
                'issuer' => trim($item['issuer'] ?? $item['organization'] ?? ''),
                'date' => trim($item['date'] ?? $item['year'] ?? '')
            ];
        }
    }
    return $out;
}

function normalizeEducationForView($items) {
    $out = [];
    foreach ((array)$items as $item) {
        if (is_string($item)) {
            $out[] = ['degree' => $item, 'institution' => '', 'period' => ''];
        } elseif (is_array($item)) {
            $out[] = [
                'degree' => trim($item['degree'] ?? $item['name'] ?? implode(' - ', array_filter(array_map('strval', $item)))),
                'institution' => trim($item['institution'] ?? $item['school'] ?? $item['university'] ?? ''),
                'period' => trim($item['period'] ?? $item['date'] ?? $item['year'] ?? '')
            ];
        }
    }
    return $out;
}

function normalizeTextListForView($items) {
    $out = [];
    foreach ((array)$items as $item) {
        if (is_array($item)) {
            $parts = [];
            foreach ($item as $value) {
                if (is_scalar($value) && trim((string)$value) !== '') $parts[] = trim((string)$value);
            }
            $text = implode(' - ', $parts);
        } else {
            $text = trim((string)$item);
        }
        if ($text !== '') $out[] = $text;
    }
    return $out;
}

function normalizeSocialForView($items) {
    $out = [];
    foreach ((array)$items as $item) {
        if (is_string($item)) {
            $url = $item;
            $platform = stripos($url, 'github') !== false ? 'github' : (stripos($url, 'linkedin') !== false ? 'linkedin' : 'link');
            $out[] = ['platform' => $platform, 'url' => $url];
        } elseif (is_array($item) && !empty($item['url'])) {
            $out[] = ['platform' => $item['platform'] ?? 'link', 'url' => $item['url']];
        }
    }
    return $out;
}
