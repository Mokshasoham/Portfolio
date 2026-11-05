<?php
/**
 * CreativePort — Autonomous AI Portfolio Builder
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/utils/resume_parser.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
$authUser = requireAuth();

// 1. Handle File Upload
$uploadResult = handleFileUpload('resume', RESUME_DIR, MAX_RESUME_SIZE, [
    'application/pdf', 'text/plain', 'application/msword', 
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]);

if (isset($uploadResult['error'])) {
    sendError($uploadResult['error']);
}

$filePath = __DIR__ . '/../' . $uploadResult['path'];
$ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

$rawText = '';
if ($ext === 'txt') {
    $rawText = file_get_contents($filePath);
} elseif ($ext === 'pdf') {
    $rawText = extractTextFromPDF($filePath);
} else {
    $rawText = extractTextFromDoc($filePath);
}

if (empty(trim($rawText))) {
    sendError('Could not extract text from the uploaded file.');
}

$baselineParsed = parseResumeContent($rawText);
$structuredProfile = buildStructuredResumeProfile($rawText);

// 2. Call Gemini API to build portfolio
if (AI_PROVIDER !== 'gemini' || empty(AI_API_KEY) || AI_API_KEY === 'YOUR_GEMINI_API_KEY') {
    $portfolio = buildPortfolioFromResumeText($rawText, $baselineParsed);
    sendSuccess(['portfolio_data' => normalizePortfolioData($portfolio, $rawText, $baselineParsed), 'resume_profile' => $structuredProfile, 'validation' => validateResumeProfile($structuredProfile)]);
    exit;
}

$prompt = "You are an expert AI portfolio builder. Your task is to analyze the following resume text and generate a COMPLETE, highly professional, structured JSON object representing a personal portfolio. 
Extract all available data, infer the target role, write a compelling 2-3 paragraph professional summary for the 'about' section, and enhance project and experience descriptions to be impactful and engaging.
Do not omit details. If the resume contains extra sections that do not fit the core fields, preserve them in additional_sections and achievements.

You MUST return strictly valid JSON matching this exact structure:
{
    \"name\": \"Full Name\",
    \"target_role\": \"Target Job Title\",
    \"contact\": {
        \"email\": \"email@example.com\",
        \"phone\": \"Phone number\",
        \"location\": \"City, Country\"
    },
    \"about\": \"A compelling, generated professional summary...\",
    \"skills\": [\"Skill 1\", \"Skill 2\"],
    \"experience\": [
        { \"title\": \"Job Title\", \"company\": \"Company\", \"period\": \"Dates\", \"description\": \"Enhanced description\" }
    ],
    \"projects\": [
        { \"title\": \"Project Name\", \"tech\": \"Technologies used\", \"link\": \"\", \"description\": \"Enhanced description\" }
    ],
    \"education\": [
        { \"degree\": \"Degree Name\", \"institution\": \"University\", \"period\": \"Dates\" }
    ],
    \"certificates\": [
        { \"name\": \"Certificate Name\", \"issuer\": \"Organization\", \"date\": \"Date\" }
    ],
    \"achievements\": [
        \"Achievement 1\", \"Achievement 2\"
    ],
    \"additional_sections\": {
        \"Section Name\": [\"Detail 1\", \"Detail 2\"]
    }
}

Resume Text:
\"\"\"
{$rawText}
\"\"\"
";

$url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . AI_API_KEY;
$payload = [
    "contents" => [["parts" => [["text" => $prompt]]]],
    "generationConfig" => ["temperature" => 0.7, "maxOutputTokens" => 2500]
];

$ch = curl_init($url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_setopt($ch, CURLOPT_TIMEOUT, 40);

$response = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($httpCode >= 200 && $httpCode < 300 && $response) {
    $result = json_decode($response, true);
    if (isset($result['candidates'][0]['content']['parts'][0]['text'])) {
        $text = $result['candidates'][0]['content']['parts'][0]['text'];
        $jsonStr = trim(preg_replace('/```(?:json|html|text)?\n(.*?)\n```/s', '$1', $text));
        $data = json_decode($jsonStr, true);
        if ($data) {
            sendSuccess(['portfolio_data' => normalizePortfolioData($data, $rawText, $baselineParsed), 'resume_profile' => $structuredProfile, 'validation' => validateResumeProfile($structuredProfile)]);
            exit;
        }
    }
}

$portfolio = buildPortfolioFromResumeText($rawText, $baselineParsed);
sendSuccess(['portfolio_data' => normalizePortfolioData($portfolio, $rawText, $baselineParsed), 'resume_profile' => $structuredProfile, 'validation' => validateResumeProfile($structuredProfile)]);

// ═══════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════

function extractTextFromPDF($filePath) {
    $content = file_get_contents($filePath);
    if (!$content) return '';
    
    $text = '';
    
    // Attempt to extract text from plain BT/ET blocks
    if (preg_match_all('/BT\s*(.*?)\s*ET/s', $content, $matches)) {
        foreach ($matches[1] as $block) {
            if (preg_match_all('/\[|\((.*?)\)|\]/', $block, $textMatches)) {
                foreach($textMatches[1] as $tm) if($tm) $text .= $tm . ' ';
                $text .= "\n";
            }
        }
    }
    
    // If very little text found, try to decode compressed streams
    if (strlen(trim($text)) < 50) {
        if (preg_match_all('/stream\s*(.*?)\s*endstream/s', $content, $streams)) {
            foreach ($streams[1] as $stream) {
                $decoded = @gzuncompress(trim($stream));
                if ($decoded) {
                    if (preg_match_all('/\((.*?)\)/', $decoded, $textMatches)) {
                        $text .= implode(' ', $textMatches[1]) . "\n";
                    }
                }
            }
        }
    }
    
    // Final cleanup: remove non-printable chars but keep basic formatting
    $text = preg_replace('/[^\x20-\x7E\n]/', '', $text);
    return trim(preg_replace('/\n{3,}/', "\n\n", $text));
}

function extractTextFromDoc($filePath) {
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    if ($ext === 'docx') {
        $zip = new ZipArchive();
        if ($zip->open($filePath) === true) {
            $content = $zip->getFromName('word/document.xml');
            $zip->close();
            if ($content) return preg_replace('/\s+/', ' ', strip_tags($content));
        }
    }
    return trim(preg_replace('/[^\x20-\x7E\n]/', '', file_get_contents($filePath)));
}

function buildPortfolioFromResumeText($text, $parsed) {
    $sections = splitResumeSections($text);
    $location = $parsed['location'] ?? '';
    if ($location && stripos($parsed['name'] ?? '', $location) !== false && !preg_match('/(?:location|based|city|address)\s*:/i', $text)) {
        $location = '';
    }

    $contact = [
        'email' => $parsed['email'] ?? '',
        'phone' => $parsed['phone'] ?? '',
        'location' => $location
    ];

    $skills = mergeUnique($parsed['skills'] ?? [], extractListItems(sectionText($sections, ['skills', 'technical skills', 'core skills', 'technologies'])));
    $summary = sectionText($sections, ['summary', 'profile', 'objective', 'about', 'professional summary']);
    $about = $summary ?: buildAboutFromLines($text);

    $experience = extractExperienceItems(sectionText($sections, ['experience', 'work experience', 'employment', 'professional experience']), $parsed['experience'] ?? []);
    $projects = extractProjectItems(sectionText($sections, ['projects', 'portfolio', 'selected projects']));
    $education = extractEducationItems(sectionText($sections, ['education', 'academic', 'qualifications']));
    $certificates = extractCertificateItems(sectionText($sections, ['certifications', 'certificates', 'licenses', 'credentials']), $parsed['certifications'] ?? []);
    $achievements = extractListItems(sectionText($sections, ['achievements', 'awards', 'honors', 'accomplishments']));
    $socialLinks = extractSocialLinks($text);
    $additional = extractAdditionalSections($sections);
    $resumeProfile = buildStructuredResumeProfile($text);

    foreach ($education as $edu) {
        $achievements[] = 'Education: ' . compactObjectToText($edu);
    }
    foreach ($additional as $label => $items) {
        foreach ($items as $item) {
            $achievements[] = ucfirst($label) . ': ' . $item;
        }
    }

    // Keep every recognised non-core section as structured content. Templates may
    // choose the layout, but this data remains unchanged when a template changes.
    foreach (['internships','hackathons','training','publications','volunteerExperience','leadership','languages','interests'] as $section) {
        if (!empty($resumeProfile[$section])) {
            $additional[$section] = array_map(fn($item) => $item['text'] ?? '', $resumeProfile[$section]);
        }
    }

    return [
        'name' => $parsed['name'] ?: inferName($text),
        'target_role' => $parsed['job_title'] ?: inferRole($text, $skills),
        'contact' => $contact,
        'about' => enhanceAbout($about, $skills, $experience),
        'skills' => $skills,
        'experience' => $experience,
        'projects' => $projects,
        'education' => $education,
        'certificates' => $certificates,
        'achievements' => array_values(array_unique(array_filter($achievements))),
        'social_links' => $socialLinks,
        'additional_sections' => $additional,
        'raw_resume_preview' => substr(cleanText($text), 0, 2000)
    ];
}

function validateResumeProfile($profile) {
    $checks = [];
    foreach (['summary','education','experience','internships','projects','certifications','achievements','hackathons','training','publications','volunteerExperience','leadership','languages','interests'] as $field) {
        $value = $profile[$field] ?? null;
        $checks[$field] = is_array($value) ? count($value) : (trim((string)$value) !== '' ? 1 : 0);
    }
    $checks['contact'] = count(array_filter((array)($profile['contact'] ?? [])));
    $checks['skills'] = array_sum(array_map('count', (array)($profile['skills'] ?? [])));
    $checks['links'] = count($profile['socialLinks'] ?? []);
    return ['sections_found' => $checks, 'needs_review' => array_keys(array_filter($checks, fn($count) => $count === 0))];
}

function normalizePortfolioData($data, $rawText, $parsed = []) {
    $fallback = buildPortfolioFromResumeText($rawText, $parsed);
    $data = is_array($data) ? $data : [];
    $contact = array_merge($fallback['contact'], is_array($data['contact'] ?? null) ? $data['contact'] : []);

    $normalized = [
        'name' => firstNonEmpty([$data['name'] ?? null, $fallback['name'], 'Portfolio Owner']),
        'target_role' => firstNonEmpty([$data['target_role'] ?? null, $data['job_title'] ?? null, $fallback['target_role'], 'Professional']),
        'contact' => $contact,
        'about' => firstNonEmpty([$data['about'] ?? null, $data['bio'] ?? null, $fallback['about']]),
        'skills' => mergeUnique($data['skills'] ?? [], $fallback['skills']),
        'experience' => normalizeExperience($data['experience'] ?? [], $fallback['experience']),
        'projects' => normalizeProjects($data['projects'] ?? [], $fallback['projects']),
        'education' => normalizeEducation($data['education'] ?? [], $fallback['education']),
        'certificates' => normalizeCertificates($data['certificates'] ?? ($data['certifications'] ?? []), $fallback['certificates']),
        'achievements' => normalizeStringList($data['achievements'] ?? [], $fallback['achievements']),
        'social_links' => normalizeSocialLinks($data['social_links'] ?? [], $fallback['social_links']),
        'additional_sections' => array_merge($fallback['additional_sections'], is_array($data['additional_sections'] ?? null) ? $data['additional_sections'] : []),
        'raw_resume_preview' => $data['raw_resume_preview'] ?? $fallback['raw_resume_preview']
    ];

    foreach ($normalized['education'] as $edu) {
        $normalized['achievements'][] = 'Education: ' . compactObjectToText($edu);
    }
    foreach ($normalized['additional_sections'] as $label => $items) {
        foreach ((array)$items as $item) {
            if (is_scalar($item)) $normalized['achievements'][] = ucfirst((string)$label) . ': ' . trim((string)$item);
        }
    }
    $normalized['achievements'] = array_values(array_unique(array_filter($normalized['achievements'])));
    $normalized['certifications'] = $normalized['certificates'];

    return $normalized;
}

function splitResumeSections($text) {
    $lines = preg_split('/\R/', cleanText($text));
    $sections = ['header' => []];
    $current = 'header';
    foreach ($lines as $line) {
        $trim = trim($line);
        if ($trim === '') continue;
        $key = strtolower(trim($trim, " :-\t"));
        if (preg_match('/^(summary|profile|objective|about|professional summary|skills|technical skills|core skills|technologies|experience|work experience|employment|professional experience|projects|portfolio|selected projects|education|academic|qualifications|certifications|certificates|licenses|credentials|achievements|awards|honors|accomplishments|publications|languages|interests|volunteer|volunteering|leadership|references)$/i', $key)) {
            $current = $key;
            if (!isset($sections[$current])) $sections[$current] = [];
            continue;
        }
        $sections[$current][] = $trim;
    }
    return $sections;
}

function sectionText($sections, $names) {
    $parts = [];
    foreach ($names as $name) {
        $key = strtolower($name);
        if (!empty($sections[$key])) $parts = array_merge($parts, $sections[$key]);
    }
    return trim(implode("\n", $parts));
}

function extractListItems($text) {
    $items = [];
    foreach (preg_split('/\R|,|;|\|/', $text) as $line) {
        $line = trim(preg_replace('/^[-*•\x{2022}\d.)\s]+/u', '', $line));
        if ($line !== '' && strlen($line) > 1) $items[] = $line;
    }
    return array_values(array_unique($items));
}

function extractExperienceItems($text, $parsedExperience = []) {
    $items = [];
    $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', $text))));
    $current = null;
    foreach ($lines as $line) {
        $cleanLine = trim(preg_replace('/^[-*•]\s*/u', '', $line));
        if (preg_match('/^(.+?)\s+at\s+(.+?)(?:\s*\((.*?)\))?$/i', $cleanLine, $m)) {
            if ($current) $items[] = $current;
            $current = ['title' => trim($m[1]), 'company' => trim($m[2]), 'period' => trim($m[3] ?? extractPeriod($cleanLine)), 'description' => ''];
        } elseif (preg_match('/(engineer|developer|designer|manager|analyst|architect|consultant|intern|lead|director|specialist|administrator|coordinator)/i', $cleanLine) && strlen($cleanLine) < 140) {
            if ($current) $items[] = $current;
            $current = ['title' => $cleanLine, 'company' => '', 'period' => extractPeriod($cleanLine), 'description' => ''];
        } elseif ($current && $current['company'] === '' && strlen($cleanLine) < 100 && !preg_match('/^[-*•]/u', $line)) {
            $current['company'] = $cleanLine;
        } elseif ($current) {
            $current['description'] .= ($current['description'] ? ' ' : '') . $cleanLine;
            if (!$current['period']) $current['period'] = extractPeriod($cleanLine);
        }
    }
    if ($current) $items[] = $current;

    if (empty($items)) {
        foreach ($parsedExperience as $exp) {
            $items[] = [
                'title' => $exp['title'] ?? $exp['role'] ?? 'Professional Experience',
                'company' => $exp['company'] ?? '',
                'period' => $exp['period'] ?? $exp['duration'] ?? '',
                'description' => $exp['description'] ?? ''
            ];
        }
    }
    return normalizeExperience($items, []);
}

function extractProjectItems($text) {
    $items = [];
    $bulletLines = array_values(array_filter(array_map('trim', preg_split('/\R/', $text))));
    $bulletProjects = [];
    foreach ($bulletLines as $line) {
        if (preg_match('/^[-*•]\s*(.+?)(?::|-)\s*(.+)$/u', $line, $m)) {
            $bulletProjects[] = ['title' => trim($m[1]), 'description' => trim($m[2]), 'tech' => '', 'link' => extractFirstUrl($line)];
        }
    }
    if ($bulletProjects) return normalizeProjects($bulletProjects, []);

    $chunks = preg_split('/\n(?=[A-Z][^\n]{2,80}$)/m', trim($text));
    foreach ($chunks as $chunk) {
        $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', $chunk))));
        if (!$lines) continue;
        $title = preg_replace('/^[-*•]\s*/u', '', array_shift($lines));
        $description = trim(implode(' ', array_map(function($line) { return preg_replace('/^[-*•]\s*/u', '', $line); }, $lines)));
        $tech = '';
        if (preg_match('/(?:tech|stack|tools?|technologies)\s*:?\s*([^.;\n]+)/i', $chunk, $m)) $tech = $m[1];
        $items[] = ['title' => $title, 'description' => $description ?: $title, 'tech' => $tech, 'link' => extractFirstUrl($chunk)];
    }
    return normalizeProjects($items, []);
}

function extractEducationItems($text) {
    $items = [];
    foreach (extractListItems($text) as $line) {
        $items[] = ['degree' => $line, 'institution' => '', 'period' => extractPeriod($line)];
    }
    return normalizeEducation($items, []);
}

function extractCertificateItems($text, $parsedCertificates = []) {
    $items = [];
    foreach (array_merge(extractListItems($text), (array)$parsedCertificates) as $line) {
        $items[] = ['name' => is_array($line) ? ($line['name'] ?? compactObjectToText($line)) : $line, 'issuer' => is_array($line) ? ($line['issuer'] ?? '') : '', 'date' => is_array($line) ? ($line['date'] ?? '') : extractYear((string)$line)];
    }
    return normalizeCertificates($items, []);
}

function extractAdditionalSections($sections) {
    $known = ['header','summary','profile','objective','about','professional summary','skills','technical skills','core skills','technologies','experience','work experience','employment','professional experience','projects','portfolio','selected projects','education','academic','qualifications','certifications','certificates','licenses','credentials','achievements','awards','honors','accomplishments'];
    $additional = [];
    foreach ($sections as $key => $lines) {
        if (!in_array($key, $known, true) && !empty($lines)) $additional[$key] = extractListItems(implode("\n", $lines));
    }
    return $additional;
}

function normalizeExperience($items, $fallback) {
    $out = [];
    foreach (array_merge((array)$items, (array)$fallback) as $item) {
        if (is_string($item)) $item = ['title' => 'Experience', 'description' => $item];
        if (!is_array($item)) continue;
        $out[] = [
            'title' => trim($item['title'] ?? $item['role'] ?? 'Professional Experience'),
            'company' => trim($item['company'] ?? $item['organization'] ?? ''),
            'period' => trim($item['period'] ?? $item['duration'] ?? $item['date'] ?? ''),
            'description' => trim($item['description'] ?? $item['summary'] ?? compactObjectToText($item))
        ];
    }
    return dedupeObjects($out, 'title');
}

function normalizeProjects($items, $fallback) {
    $out = [];
    foreach (array_merge((array)$items, (array)$fallback) as $item) {
        if (is_string($item)) $item = ['title' => $item, 'description' => $item];
        if (!is_array($item)) continue;
        $tech = $item['tech'] ?? $item['tech_stack'] ?? $item['technologies'] ?? '';
        $out[] = [
            'title' => trim($item['title'] ?? $item['name'] ?? 'Project'),
            'description' => trim($item['description'] ?? $item['summary'] ?? compactObjectToText($item)),
            'tech' => is_array($tech) ? implode(', ', $tech) : trim((string)$tech),
            'link' => trim($item['link'] ?? $item['live_link'] ?? $item['github_link'] ?? $item['url'] ?? '')
        ];
    }
    return dedupeObjects($out, 'title');
}

function normalizeEducation($items, $fallback) {
    $out = [];
    foreach (array_merge((array)$items, (array)$fallback) as $item) {
        if (is_string($item)) $item = ['degree' => $item];
        if (!is_array($item)) continue;
        $out[] = [
            'degree' => trim($item['degree'] ?? $item['name'] ?? compactObjectToText($item)),
            'institution' => trim($item['institution'] ?? $item['school'] ?? $item['university'] ?? ''),
            'period' => trim($item['period'] ?? $item['date'] ?? $item['year'] ?? '')
        ];
    }
    return dedupeObjects($out, 'degree');
}

function normalizeCertificates($items, $fallback) {
    $out = [];
    foreach (array_merge((array)$items, (array)$fallback) as $item) {
        if (is_string($item)) $item = ['name' => $item];
        if (!is_array($item)) continue;
        $out[] = [
            'name' => trim($item['name'] ?? $item['title'] ?? compactObjectToText($item)),
            'issuer' => trim($item['issuer'] ?? $item['organization'] ?? ''),
            'date' => trim($item['date'] ?? $item['year'] ?? extractYear(compactObjectToText($item)))
        ];
    }
    return dedupeObjects($out, 'name');
}

function normalizeStringList($items, $fallback = []) {
    $out = [];
    foreach (array_merge((array)$items, (array)$fallback) as $item) {
        $text = is_array($item) ? compactObjectToText($item) : trim((string)$item);
        if ($text !== '') $out[] = $text;
    }
    return array_values(array_unique($out));
}

function normalizeSocialLinks($items, $fallback = []) {
    $links = [];
    foreach (array_merge((array)$items, (array)$fallback) as $item) {
        if (is_string($item)) $item = ['url' => $item];
        if (!is_array($item) || empty($item['url'])) continue;
        $url = $item['url'];
        $links[] = ['platform' => $item['platform'] ?? inferPlatform($url), 'url' => $url];
    }
    return dedupeObjects($links, 'url');
}

function extractSocialLinks($text) {
    preg_match_all('/https?:\/\/[^\s)]+/i', $text, $matches);
    return normalizeSocialLinks($matches[0] ?? [], []);
}

function inferPlatform($url) {
    foreach (['github', 'linkedin', 'twitter', 'x', 'dribbble', 'behance', 'instagram'] as $platform) {
        if (stripos($url, $platform) !== false) return $platform === 'x' ? 'twitter' : $platform;
    }
    return 'link';
}

function cleanText($text) {
    $text = str_replace(["\r\n", "\r"], "\n", $text);
    return trim(preg_replace('/[ \t]+/', ' ', $text));
}

function inferName($text) {
    foreach (preg_split('/\R/', cleanText($text)) as $line) {
        $line = trim($line);
        if (strlen($line) >= 3 && strlen($line) <= 60 && !preg_match('/[@0-9]|resume|curriculum/i', $line)) return $line;
    }
    return 'Portfolio Owner';
}

function inferRole($text, $skills) {
    if (preg_match('/\b(Senior|Junior|Lead|Principal|Staff)?\s*(Software|Full Stack|Frontend|Backend|Data|DevOps|Cloud|UI\/UX|Product)?\s*(Engineer|Developer|Designer|Manager|Analyst|Architect|Consultant)\b/i', $text, $m)) {
        return trim($m[0]);
    }
    return !empty($skills) ? $skills[0] . ' Professional' : 'Professional';
}

function buildAboutFromLines($text) {
    $lines = array_values(array_filter(array_map('trim', preg_split('/\R/', cleanText($text)))));
    $usable = [];
    foreach ($lines as $line) {
        if (strlen($line) > 40 && !preg_match('/@|https?:\/\//i', $line)) $usable[] = $line;
        if (count($usable) >= 3) break;
    }
    return implode(' ', $usable);
}

function enhanceAbout($about, $skills, $experience) {
    $about = trim($about);
    if (preg_match('/^[-*•]/u', $about)) $about = '';
    if (strlen($about) >= 120) return $about;
    $skillText = $skills ? ' Core strengths include ' . implode(', ', array_slice($skills, 0, 8)) . '.' : '';
    $expText = $experience ? ' Experience includes ' . implode('; ', array_map(function($e) { return trim(($e['title'] ?? '') . ' ' . (($e['company'] ?? '') ? 'at ' . $e['company'] : '')); }, array_slice($experience, 0, 3))) . '.' : '';
    return trim(($about ?: 'A results-oriented professional with a background reflected across the uploaded resume.') . $skillText . $expText);
}

function mergeUnique($a, $b) {
    return array_values(array_unique(array_filter(array_map('trim', array_map('strval', array_merge((array)$a, (array)$b))))));
}

function firstNonEmpty($values) {
    foreach ($values as $value) if (is_string($value) && trim($value) !== '') return trim($value);
    return '';
}

function extractPeriod($text) {
    return preg_match('/((?:19|20)\d{2}\s*(?:-|–|to)\s*(?:(?:19|20)\d{2}|present|current|now)|(?:19|20)\d{2})/i', $text, $m) ? $m[1] : '';
}

function extractYear($text) {
    return preg_match('/(?:19|20)\d{2}/', $text, $m) ? $m[0] : '';
}

function extractFirstUrl($text) {
    return preg_match('/https?:\/\/[^\s)]+/i', $text, $m) ? $m[0] : '';
}

function compactObjectToText($item) {
    if (!is_array($item)) return trim((string)$item);
    $parts = [];
    foreach ($item as $value) {
        if (is_scalar($value) && trim((string)$value) !== '') $parts[] = trim((string)$value);
    }
    return implode(' - ', array_unique($parts));
}

function dedupeObjects($items, $key) {
    $seen = [];
    $out = [];
    foreach ($items as $item) {
        $value = strtolower(trim($item[$key] ?? compactObjectToText($item)));
        if ($value === '' || isset($seen[$value])) continue;
        $seen[$value] = true;
        $out[] = $item;
    }
    return $out;
}
?>
