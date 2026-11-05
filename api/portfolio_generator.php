<?php
/**
 * CreativePort — Portfolio Generator API
 * Main endpoint for generating user portfolios from resume data
 * Orchestrates resume parsing, AI processing, template selection, and final generation
 */
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/template_engine.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    sendError('Method not allowed', 405);
}

$authUser = requireAuth();
$action = $_POST['action'] ?? '';

// ═══════════════════════════════════════════════════════════
// MAIN ACTIONS
// ═══════════════════════════════════════════════════════════

switch ($action) {

    // ─── ANALYZE & PARSE RESUME ───────────────────────────
    case 'parse_resume':
        $upload = handleFileUpload('resume', RESUME_DIR, MAX_RESUME_SIZE, [
            'application/pdf', 'text/plain',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        ]);

        if (isset($upload['error'])) {
            sendError($upload['error']);
        }

        $filePath = __DIR__ . '/../' . $upload['path'];
        $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $rawText = '';

        if ($ext === 'txt') {
            $rawText = file_get_contents($filePath);
        } elseif ($ext === 'pdf') {
            require_once __DIR__ . '/utils/pdf_parser.php';
            $rawText = extractTextFromPDF($filePath);
        } else {
            require_once __DIR__ . '/utils/doc_parser.php';
            $rawText = extractTextFromDoc($filePath);
        }

        if (empty(trim($rawText))) {
            sendError('Could not extract text. Please try a PDF or TXT file.');
        }

        // Parse resume content
        require_once __DIR__ . '/utils/resume_parser.php';
        $parsed = parseResumeContent($rawText);

        // Use AI to enhance parsing if available
        if (AI_PROVIDER === 'gemini' && !empty(AI_API_KEY) && AI_API_KEY !== 'YOUR_GEMINI_API_KEY') {
            $enhanced = enhanceParsingWithAI($rawText, $parsed);
            if ($enhanced) {
                $parsed = array_merge($parsed, $enhanced);
            }
        }

        sendSuccess([
            'parsed' => $parsed,
            'file_path' => $upload['path'],
            'raw_preview' => substr($rawText, 0, 300)
        ], 'Resume parsed successfully');
        break;

    // ─── GET TEMPLATE PREVIEWS ────────────────────────────
    case 'get_templates':
        $templates = [
            [
                'id' => 'minimal',
                'name' => 'Minimal',
                'description' => 'Clean, professional design focusing on your work',
                'preview_image' => 'https://via.placeholder.com/300x200?text=Minimal',
                'color_scheme' => ['#667eea', '#ffffff', '#333333'],
                'features' => ['Sticky header', 'Clean typography', 'Simple layout']
            ],
            [
                'id' => 'modern',
                'name' => 'Modern',
                'description' => 'Vibrant gradients and dynamic cards',
                'preview_image' => 'https://via.placeholder.com/300x200?text=Modern',
                'color_scheme' => ['#667eea', '#764ba2', '#ffffff'],
                'features' => ['Gradient backgrounds', 'Card-based sections', 'Animated hover effects']
            ],
            [
                'id' => 'creative',
                'name' => 'Creative',
                'description' => 'Artistic with animations and unique design',
                'preview_image' => 'https://via.placeholder.com/300x200?text=Creative',
                'color_scheme' => ['#667eea', '#764ba2', '#0a0e27'],
                'features' => ['Animated elements', 'Timeline experience', 'Dark theme with neon']
            ],
            [
                'id' => 'developer',
                'name' => 'Developer',
                'description' => 'Terminal-style with code focus',
                'preview_image' => 'https://via.placeholder.com/300x200?text=Developer',
                'color_scheme' => ['#58a6ff', '#0d1117', '#c9d1d9'],
                'features' => ['GitHub-inspired design', 'Code blocks', 'Minimalist aesthetic']
            ]
        ];

        sendSuccess(['templates' => $templates]);
        break;

    // ─── RENDER TEMPLATE PREVIEW ──────────────────────────
    case 'preview_template':
        $template_id = trim($_POST['template_id'] ?? '');
        $user_data = $_POST['user_data'] ? json_decode($_POST['user_data'], true) : null;

        if (empty($template_id)) {
            sendError('Template ID required');
        }

        $template_file = __DIR__ . '/../templates/' . preg_replace('/[^a-z0-9_-]/', '', $template_id) . '.html';
        if (!file_exists($template_file)) {
            sendError('Template not found');
        }

        // Use demo data if no user data provided
        $data = $user_data ?? TemplateEngine::getDemo($template_id);
        $sections = [
            'about' => true,
            'skills' => true,
            'projects' => true,
            'experience' => true,
            'certifications' => true,
            'contact' => true
        ];

        $html = TemplateEngine::render($template_file, $data, $sections);

        // Return preview as HTML in data  
        sendSuccess(['html' => $html, 'template_id' => $template_id], 'Template preview generated');
        break;

    // ─── GENERATE FINAL PORTFOLIO ────────────────────────
    case 'generate_portfolio':
        $portfolio_data = $_POST['portfolio_data'] ? json_decode($_POST['portfolio_data'], true) : null;
        $template_id = trim($_POST['template_id'] ?? '');
        $is_public = isset($_POST['is_public']) ? (bool)$_POST['is_public'] : false;

        if (!$portfolio_data) {
            sendError('Portfolio data required');
        }
        if (empty($template_id)) {
            sendError('Template selection required');
        }

        // Validate template
        $template_file = __DIR__ . '/../templates/' . preg_replace('/[^a-z0-9_-]/', '', $template_id) . '.html';
        if (!file_exists($template_file)) {
            sendError('Invalid template selected');
        }

        // Get or create template record
        $stmt = $conn->prepare("SELECT id FROM templates WHERE slug = ?");
        $stmt->bind_param("s", $template_id);
        $stmt->execute();
        $template_result = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $template_db_id = $template_result['id'] ?? null;

        // Prepare portfolio data
        $portfolio_data['current_year'] = date('Y');
        $content_json = json_encode($portfolio_data);
        $sections_config = [
            'about' => !empty($portfolio_data['about']),
            'skills' => !empty($portfolio_data['skills']),
            'projects' => !empty($portfolio_data['projects']),
            'experience' => !empty($portfolio_data['experience']),
            'certifications' => !empty($portfolio_data['certifications']),
            'contact' => !empty($portfolio_data['email'] || $portfolio_data['phone'])
        ];
        $sections_json = json_encode($sections_config);

        // Generate unique slug
        $slug = sanitizeSlug($portfolio_data['name'] ?? 'portfolio');
        $slug_base = $slug;
        $counter = 1;
        while (portfolioSlugExists($conn, $slug, $authUser['id'])) {
            $slug = $slug_base . '-' . $counter++;
        }

        // Create portfolio record
        $status = 'published';
        $now = date('Y-m-d H:i:s');
        
        $stmt = $conn->prepare("
            INSERT INTO portfolios 
            (user_id, template_id, slug, title, content_json, sections_visibility, status, is_public, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $title = ($portfolio_data['name'] ?? 'Portfolio') . ' - ' . ($portfolio_data['job_title'] ?? 'Portfolio');
        $stmt->bind_param(
            "iisssssiss",
            $authUser['id'],
            $template_db_id,
            $slug,
            $title,
            $content_json,
            $sections_json,
            $status,
            $is_public,
            $now,
            $now
        );

        if (!$stmt->execute()) {
            sendError('Failed to create portfolio: ' . $conn->error);
        }

        $portfolio_id = $stmt->insert_id;
        $stmt->close();

        // Render final HTML
        $html = TemplateEngine::render($template_file, $portfolio_data, $sections_config);

        // Save HTML file (optional - for static export)
        $html_dir = UPLOAD_DIR . 'portfolios/';
        if (!is_dir($html_dir)) {
            mkdir($html_dir, 0755, true);
        }
        file_put_contents($html_dir . $portfolio_id . '.html', $html);

        sendSuccess([
            'portfolio_id' => $portfolio_id,
            'slug' => $slug,
            'url' => '/portfolio/index.php?slug=' . urlencode($slug),
            'preview_html' => substr($html, 0, 100),
            'is_public' => $is_public
        ], 'Portfolio generated successfully');
        break;

    // ─── SWITCH TEMPLATE ──────────────────────────────────
    case 'switch_template':
        $portfolio_id = (int)($_POST['portfolio_id'] ?? 0);
        $new_template_id = trim($_POST['template_id'] ?? '');

        if ($portfolio_id <= 0 || empty($new_template_id)) {
            sendError('Portfolio ID and template ID required');
        }

        // Get existing portfolio
        $stmt = $conn->prepare("SELECT * FROM portfolios WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $portfolio_id, $authUser['id']);
        $stmt->execute();
        $portfolio = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$portfolio) {
            sendError('Portfolio not found');
        }

        // Validate new template
        $template_file = __DIR__ . '/../templates/' . preg_replace('/[^a-z0-9_-]/', '', $new_template_id) . '.html';
        if (!file_exists($template_file)) {
            sendError('Invalid template selected');
        }

        // Get template ID
        $stmt = $conn->prepare("SELECT id FROM templates WHERE slug = ?");
        $stmt->bind_param("s", $new_template_id);
        $stmt->execute();
        $template_result = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        // Update portfolio template
        $sections = json_decode($portfolio['sections_visibility'], true);
        $portfolio_data = json_decode($portfolio['content_json'], true);

        $stmt = $conn->prepare("UPDATE portfolios SET template_id = ?, updated_at = NOW() WHERE id = ?");
        $stmt->bind_param("ii", $template_result['id'] ?? null, $portfolio_id);
        $stmt->execute();
        $stmt->close();

        // Re-render with new template
        $html = TemplateEngine::render($template_file, $portfolio_data, $sections);

        // Save updated HTML
        $html_dir = UPLOAD_DIR . 'portfolios/';
        if (!is_dir($html_dir)) {
            mkdir($html_dir, 0755, true);
        }
        file_put_contents($html_dir . $portfolio_id . '.html', $html);

        sendSuccess([
            'portfolio_id' => $portfolio_id,
            'template_id' => $new_template_id,
            'message' => 'Template switched successfully'
        ], 'Template switched');
        break;

    // ─── GET AI SUGGESTIONS ───────────────────────────────
    case 'get_suggestions':
        $portfolio_data = $_POST['portfolio_data'] ? json_decode($_POST['portfolio_data'], true) : null;

        if (!$portfolio_data) {
            sendError('Portfolio data required');
        }

        $suggestions = [];

        // Check missing or short content
        if (empty($portfolio_data['about']) || strlen($portfolio_data['about'] ?? '') < 100) {
            $suggestions[] = [
                'type' => 'about',
                'title' => 'Enhance Your Bio',
                'message' => 'Your bio could be more detailed. Try adding more about your experience and values.',
                'icon' => 'fa-pen-fancy'
            ];
        }

        if (count($portfolio_data['projects'] ?? []) < 3) {
            $suggestions[] = [
                'type' => 'projects',
                'title' => 'Add More Projects',
                'message' => 'Showcase at least 3 projects to make your portfolio more impressive.',
                'icon' => 'fa-briefcase'
            ];
        }

        if (count($portfolio_data['skills'] ?? []) < 8) {
            $suggestions[] = [
                'type' => 'skills',
                'title' => 'List More Skills',
                'message' => 'Add at least 8 key skills to better represent your expertise.',
                'icon' => 'fa-star'
            ];
        }

        if (empty($portfolio_data['certifications']) || count($portfolio_data['certifications']) < 2) {
            $suggestions[] = [
                'type' => 'certifications',
                'title' => 'Add Certifications',
                'message' => 'Add your certifications and awards to build credibility.',
                'icon' => 'fa-medal'
            ];
        }

        sendSuccess(['suggestions' => $suggestions]);
        break;

    default:
        sendError('Unknown action: ' . $action);
}

// ═══════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════

/**
 * Sanitize portfolio slug
 */
function sanitizeSlug($text) {
    $slug = strtolower(trim($text));
    $slug = preg_replace('/[^a-z0-9]+/', '-', $slug);
    $slug = trim($slug, '-');
    return substr($slug, 0, 50);
}

/**
 * Check if slug already exists for user
 */
function portfolioSlugExists($conn, $slug, $user_id) {
    $stmt = $conn->prepare("SELECT id FROM portfolios WHERE slug = ? AND user_id = ?");
    $stmt->bind_param("si", $slug, $user_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $exists = $result->num_rows > 0;
    $stmt->close();
    return $exists;
}

/**
 * Enhance resume parsing with AI (if configured)
 */
function enhanceParsingWithAI($raw_text, $current_parsing) {
    if (!function_exists('curl_init')) {
        return null;
    }

    $prompt = "Extract and enhance the following resume data into structured JSON. Return ONLY valid JSON with these keys: name, job_title, skills (array), experience (array of {company, role, duration, description}), projects (array of {title, description}), certifications (array), contact (with email, phone). Here's the resume:\n\n" . substr($raw_text, 0, 2000);

    $url = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . AI_API_KEY;
    $payload = [
        'contents' => [['parts' => [['text' => $prompt]]]],
        'generationConfig' => ['temperature' => 0.2, 'maxOutputTokens' => 1500]
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $apiResponse = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode < 200 || $httpCode >= 300 || !$apiResponse) {
        return null;
    }

    $result = json_decode($apiResponse, true);
    $response = $result['candidates'][0]['content']['parts'][0]['text'] ?? null;
    
    if ($response) {
        $json = trim(preg_replace('/```(?:json)?\s*(.*?)\s*```/s', '$1', $response));
        $enhanced = json_decode($json, true);
        return is_array($enhanced) ? $enhanced : null;
    }
    
    return null;
}
?>
