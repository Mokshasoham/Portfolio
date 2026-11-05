<?php
/**
 * CreativePort — AI Content Generation API
 * Supports Gemini API (and fallback Mock Mode)
 */
require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);

$authUser = requireAuth();
$data = getRequestBody();
$action = $data['action'] ?? '';

// Check provider
$useGemini = (AI_PROVIDER === 'gemini' && !empty(AI_API_KEY) && AI_API_KEY !== 'YOUR_GEMINI_API_KEY');

switch ($action) {

    // ─── IMPROVE TEXT ──────────────────────────────────────
    case 'improve_text':
        $text = trim($data['text'] ?? '');
        $type = $data['type'] ?? 'general'; // about, project, experience

        if (empty($text)) sendError('Text is required.');

        if ($useGemini) {
            $prompt = "Improve the following {$type} text for a professional portfolio to make it sound more professional, engaging, and grammatically correct. Do not add any conversational filler, just return the improved text:\n\n{$text}";
            $improved = callGeminiApi($prompt);
            if ($improved) sendSuccess(['improved_text' => $improved, 'provider' => 'gemini']);
        }
        
        // Fallback to mock
        $improved = mockImproveText($text, $type);
        sendSuccess(['improved_text' => $improved, 'provider' => 'mock_fallback']);
        break;

    // ─── GENERATE ABOUT ────────────────────────────────────
    case 'generate_about':
        $name = trim($data['name'] ?? '');
        $skills = is_array($data['skills'] ?? []) ? implode(', ', $data['skills']) : ($data['skills'] ?? '');
        $experience = trim($data['experience'] ?? '');
        $role = trim($data['role'] ?? 'professional');

        if ($useGemini) {
            $prompt = "Write a professional, cinematic, and engaging 'About Me' biography for a portfolio. The person's name is {$name}. Their role is {$role}. Their skills include: {$skills}. Some experience: {$experience}. Write 2-3 paragraphs. Do not use conversational filler, just return the biography.";
            $about = callGeminiApi($prompt);
            if ($about) sendSuccess(['generated_text' => $about, 'provider' => 'gemini']);
        }
        
        $about = mockGenerateAbout($name, $skills, $experience, $role);
        sendSuccess(['generated_text' => $about, 'provider' => 'mock_fallback']);
        break;

    // ─── GENERATE PROJECT DESCRIPTION ──────────────────────
    case 'generate_project_desc':
        $projectName = trim($data['project_name'] ?? '');
        $techStack = is_array($data['tech_stack'] ?? []) ? implode(', ', $data['tech_stack']) : ($data['tech_stack'] ?? '');
        $brief = trim($data['brief'] ?? '');

        if ($useGemini) {
            $prompt = "Write a professional project description for a portfolio. The project is called '{$projectName}'. The technologies used are: {$techStack}. Additional details: {$brief}. Make it sound impressive, focus on problem-solving and value. 1-2 paragraphs. Do not use conversational filler.";
            $desc = callGeminiApi($prompt);
            if ($desc) sendSuccess(['generated_text' => $desc, 'provider' => 'gemini']);
        }
        
        $desc = mockGenerateProjectDesc($projectName, $techStack, $brief);
        sendSuccess(['generated_text' => $desc, 'provider' => 'mock_fallback']);
        break;

    // ─── SUGGEST SKILLS ────────────────────────────────────
    case 'suggest_skills':
        $currentSkills = is_array($data['current_skills'] ?? []) ? implode(', ', $data['current_skills']) : ($data['current_skills'] ?? '');
        $role = trim($data['role'] ?? 'professional');

        if ($useGemini) {
            $prompt = "Suggest 6 relevant professional skills for a {$role}. They already have these skills: {$currentSkills}. Do not repeat existing skills. Return ONLY a comma-separated list of the 6 suggested skills. No conversational filler.";
            $response = callGeminiApi($prompt);
            if ($response) {
                $suggested = array_map('trim', explode(',', $response));
                // Clean up possible formatting
                $suggested = array_filter(array_map(function($s) {
                    return trim(preg_replace('/^[-*•]\s*|^\d+\.\s*/', '', $s));
                }, $suggested));
                
                sendSuccess(['suggested_skills' => array_values($suggested), 'provider' => 'gemini']);
            }
        }
        
        $currentArray = is_array($data['current_skills'] ?? []) ? $data['current_skills'] : [];
        $suggested = mockSuggestSkills($currentArray, $role);
        sendSuccess(['suggested_skills' => $suggested, 'provider' => 'mock_fallback']);
        break;

    // ─── GENERATE SUMMARY ──────────────────────────────────
    case 'generate_summary':
        $portfolioData = $data['portfolio_data'] ?? [];
        $jsonStr = json_encode($portfolioData);

        if ($useGemini) {
            $prompt = "Write a short, powerful 2-sentence executive summary based on this portfolio data: {$jsonStr}. Do not use conversational filler.";
            $summary = callGeminiApi($prompt);
            if ($summary) sendSuccess(['generated_text' => $summary, 'provider' => 'gemini']);
        }
        
        $summary = mockGenerateSummary($portfolioData);
        sendSuccess(['generated_text' => $summary, 'provider' => 'mock_fallback']);
        break;

    default:
        sendError('Invalid action. Valid: improve_text, generate_about, generate_project_desc, suggest_skills, generate_summary');
        break;
}

// ═══════════════════════════════════════════════════════════
// GEMINI API FUNCTION
// ═══════════════════════════════════════════════════════════

function callGeminiApi($prompt) {
    if (empty(AI_API_KEY) || AI_API_KEY === 'YOUR_GEMINI_API_KEY') return false;

    $url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . AI_API_KEY;
    
    $payload = [
        "contents" => [
            [
                "parts" => [
                    ["text" => $prompt]
                ]
            ]
        ],
        "generationConfig" => [
            "temperature" => 0.7,
            "maxOutputTokens" => 800
        ]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json'
    ]);
    
    // Set timeout to prevent hanging
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode >= 200 && $httpCode < 300 && $response) {
        $result = json_decode($response, true);
        if (isset($result['candidates'][0]['content']['parts'][0]['text'])) {
            $text = $result['candidates'][0]['content']['parts'][0]['text'];
            return trim(preg_replace('/```(?:json|html|text)?\n(.*?)\n```/s', '$1', $text));
        }
    }
    
    return false; // Fallback to mock on error
}

// ═══════════════════════════════════════════════════════════
// MOCK AI FUNCTIONS (FALLBACK)
// ═══════════════════════════════════════════════════════════

function mockImproveText($text, $type) {
    $text = ucfirst(trim($text));
    $text = preg_replace('/\s+/', ' ', $text);
    if (!preg_match('/[.!?]$/', $text)) $text .= '.';
    $text = preg_replace_callback('/(?<=^|[.!?]\s)(\w)/', function($m) { return strtoupper($m[1]); }, $text);
    return $text;
}

function mockGenerateAbout($name, $skills, $experience, $role) {
    $skillStr = is_array($skills) ? implode(', ', array_slice($skills, 0, 5)) : $skills;
    $roleTitle = ucwords(str_replace(['_', '-'], ' ', $role));
    $templates = [
        "I am {$name}, a passionate {$roleTitle} with expertise in {$skillStr}. With {$experience} of experience in the industry, I specialize in building innovative solutions that drive results. I am committed to continuous learning and delivering high-quality work that exceeds expectations.",
        "Hi, I'm {$name} — a dedicated {$roleTitle} skilled in {$skillStr}. Over {$experience} of professional experience, I have developed a strong foundation in creating impactful digital solutions. I thrive on solving complex problems and turning ideas into reality.",
        "As a {$roleTitle} with {$experience} of hands-on experience, I bring deep expertise in {$skillStr} to every project I undertake. My name is {$name}, and I am passionate about leveraging technology to create meaningful, user-centered experiences."
    ];
    return $templates[array_rand($templates)];
}

function mockGenerateProjectDesc($projectName, $techStack, $brief) {
    $tech = is_array($techStack) ? implode(', ', $techStack) : $techStack;
    $name = $projectName ?: 'This project';
    if (!empty($brief)) return "{$name} is a comprehensive solution built with {$tech}. {$brief} The project showcases modern development practices, clean architecture, and a focus on user experience. Key features include responsive design, optimized performance, and intuitive navigation.";
    return "{$name} is an innovative application developed using {$tech}. This project demonstrates proficiency in full-stack development, featuring a clean user interface, robust backend logic, and seamless integration between components. Built with scalability and maintainability in mind.";
}

function mockSuggestSkills($currentSkills, $role) {
    $skillSuggestions = [
        'developer' => ['React', 'Node.js', 'TypeScript', 'Docker', 'AWS', 'Git', 'REST APIs', 'PostgreSQL', 'Redis', 'CI/CD'],
        'designer' => ['Figma', 'Adobe XD', 'Sketch', 'Photoshop', 'Illustrator', 'UI/UX', 'Prototyping', 'Typography', 'Color Theory', 'Wireframing'],
        'data_scientist' => ['Python', 'TensorFlow', 'Pandas', 'NumPy', 'Scikit-learn', 'SQL', 'Tableau', 'R', 'Machine Learning', 'Deep Learning'],
        'default' => ['Communication', 'Problem Solving', 'Team Leadership', 'Project Management', 'Agile', 'Git', 'Public Speaking', 'Critical Thinking']
    ];
    $pool = $skillSuggestions[$role] ?? $skillSuggestions['default'];
    $currentLower = array_map('strtolower', $currentSkills);
    $suggestions = array_filter($pool, function($skill) use ($currentLower) {
        return !in_array(strtolower($skill), $currentLower);
    });
    return array_values(array_slice($suggestions, 0, 6));
}

function mockGenerateSummary($portfolioData) {
    $projects = $portfolioData['projects'] ?? [];
    $skills = $portfolioData['skills'] ?? [];
    $projectCount = count($projects);
    $skillCount = count($skills);
    return "A versatile professional with expertise spanning {$skillCount} technologies and {$projectCount} notable projects. Demonstrates a strong track record of delivering high-quality solutions with a focus on modern development practices, clean code, and exceptional user experiences.";
}

$conn->close();
?>
