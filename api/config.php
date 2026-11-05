<?php
/**
 * CreativePort — Global Configuration & Helpers
 * All API endpoints include this file for DB connection, auth checks, and utilities.
 */

// ─── Setup ────────────────────────────────────────────────
ini_set('display_errors', 0);
error_reporting(E_ALL);
mysqli_report(MYSQLI_REPORT_OFF);

function sendSuccess($data = [], $message = 'Success', $code = 200) {
    header('Content-Type: application/json');
    http_response_code($code);
    echo json_encode([
        'status' => 'success',
        'success' => true,
        'message' => $message,
        'data' => $data
    ]);
    exit;
}

function sendError($message = 'An error occurred', $code = 400) {
    header('Content-Type: application/json');
    http_response_code($code);
    echo json_encode([
        'status' => 'error',
        'success' => false,
        'message' => $message,
        'error' => $message
    ]);
    exit;
}

// ─── Session ───────────────────────────────────────────────
if (session_status() === PHP_SESSION_NONE) {
    if (PHP_SAPI === 'cli') {
        $sessionPath = sys_get_temp_dir();
        if (is_writable($sessionPath)) {
            session_save_path($sessionPath);
        }
    }
    session_start();
}

// ─── CORS & Headers ────────────────────────────────────────
// header('Content-Type: application/json'); // Removed to allow HTML rendering for preview pages
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// ─── Database Connection ───────────────────────────────────
define('DB_HOST', '127.0.0.1');
define('DB_PORT', 3307);
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'portfolio_db');

$conn = @new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME, DB_PORT);
if ($conn->connect_error) {
    sendError('Database connection failed: ' . $conn->connect_error, 500);
}
$conn->set_charset('utf8mb4');

// ─── Upload Paths ──────────────────────────────────────────
define('UPLOAD_DIR', __DIR__ . '/../uploads/');
define('AVATAR_DIR', UPLOAD_DIR . 'avatars/');
define('RESUME_DIR', UPLOAD_DIR . 'resumes/');
define('PROJECT_DIR', UPLOAD_DIR . 'projects/');

// ─── AI Config ─────────────────────────────────────────────
// Set to 'openai', 'gemini', or 'mock'
define('AI_PROVIDER', 'gemini');
define('AI_API_KEY', 'YOUR_GEMINI_API_KEY'); // Replace with your actual Gemini API Key

// ─── Max upload sizes ──────────────────────────────────────
define('MAX_AVATAR_SIZE', 5 * 1024 * 1024);  // 5MB
define('MAX_RESUME_SIZE', 10 * 1024 * 1024); // 10MB
define('MAX_PROJECT_IMG_SIZE', 5 * 1024 * 1024); // 5MB

// ═══════════════════════════════════════════════════════════
// HELPER FUNCTIONS
// ═══════════════════════════════════════════════════════════

/**
 * Get JSON body from POST request
 */
function getRequestBody() {
    $json = file_get_contents('php://input');
    $data = json_decode($json, true);
    return $data ?: [];
}

/**
 * Require the user to be authenticated. Returns user data or sends 401.
 */
function requireAuth() {
    if (!isset($_SESSION['user_id'])) {
        sendError('Authentication required. Please log in.', 401);
    }
    return [
        'id' => $_SESSION['user_id'],
        'name' => $_SESSION['user_name'] ?? '',
        'email' => $_SESSION['user_email'] ?? ''
    ];
}

/**
 * Get current user if logged in, or null
 */
function getCurrentUser() {
    if (isset($_SESSION['user_id'])) {
        return [
            'id' => $_SESSION['user_id'],
            'name' => $_SESSION['user_name'] ?? '',
            'email' => $_SESSION['user_email'] ?? ''
        ];
    }
    return null;
}

/**
 * Sanitize a string for safe output
 */
function sanitize($str) {
    return trim($str);
}

/**
 * Recursively sanitize an array or string
 */
function sanitizeArray($data) {
    if (is_array($data)) {
        foreach ($data as $key => $value) {
            $data[$key] = sanitizeArray($value);
        }
        return $data;
    }
    return is_string($data) ? sanitize($data) : $data;
}

/**
 * Generate a URL-safe slug from a string
 */
function generateSlug($str) {
    $slug = strtolower(trim($str));
    $slug = preg_replace('/[^a-z0-9-]/', '-', $slug);
    $slug = preg_replace('/-+/', '-', $slug);
    $slug = trim($slug, '-');
    return $slug ?: 'portfolio-' . time();
}

/**
 * Generate a unique slug for a portfolio
 */
function generateUniqueSlug($conn, $baseSlug, $userId) {
    $slug = generateSlug($baseSlug);
    $original = $slug;
    $counter = 1;

    while (true) {
        $stmt = $conn->prepare("SELECT id FROM portfolios WHERE slug = ? AND user_id = ?");
        $stmt->bind_param("si", $slug, $userId);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            $stmt->close();
            return $slug;
        }
        $stmt->close();
        $slug = $original . '-' . $counter;
        $counter++;
    }
}

/**
 * Handle file upload with validation
 */
function handleFileUpload($fileInput, $targetDir, $maxSize, $allowedTypes) {
    if (!isset($_FILES[$fileInput]) || $_FILES[$fileInput]['error'] !== UPLOAD_ERR_OK) {
        return ['error' => 'No file uploaded or upload error occurred.'];
    }

    $file = $_FILES[$fileInput];

    // Check file size
    if ($file['size'] > $maxSize) {
        $maxMB = round($maxSize / (1024 * 1024), 1);
        return ['error' => "File too large. Maximum size is {$maxMB}MB."];
    }

    // Check file type. Some local Windows/XAMPP uploads report DOCX/PDF files as a
    // generic MIME type, so keep MIME validation but allow known resume extensions.
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowedExtensions = [
        'application/pdf' => ['pdf'],
        'text/plain' => ['txt'],
        'application/msword' => ['doc'],
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => ['docx'],
        'application/zip' => ['docx'],
        'application/octet-stream' => ['pdf', 'doc', 'docx', 'txt']
    ];
    $extensionAllowed = false;
    foreach ($allowedTypes as $allowedType) {
        if (in_array($ext, $allowedExtensions[$allowedType] ?? [], true)) {
            $extensionAllowed = true;
            break;
        }
    }

    if (!in_array($mimeType, $allowedTypes, true) && !$extensionAllowed) {
        return ['error' => 'Invalid file type: ' . $mimeType];
    }

    // Create directory if it doesn't exist
    if (!is_dir($targetDir)) {
        @mkdir($targetDir, 0755, true);
    }

    // Generate unique filename
    $filename = uniqid() . '_' . time() . '.' . $ext;
    $targetPath = $targetDir . $filename;

    if (@move_uploaded_file($file['tmp_name'], $targetPath)) {
        // Return relative path for storage
        $relativePath = str_replace(__DIR__ . '/../', '', $targetPath);
        return ['path' => $relativePath, 'filename' => $filename];
    }

    return ['error' => 'Failed to save uploaded file.'];
}

/**
 * Calculate portfolio completeness score
 */
function calculatePortfolioScore($contentJson, $user) {
    $score = 0;
    $suggestions = [];
    $content = is_string($contentJson) ? json_decode($contentJson, true) : $contentJson;
    if (!$content) $content = [];

    // Profile photo (5 pts)
    if (!empty($user['avatar'])) {
        $score += 5;
    } else {
        $suggestions[] = 'Add a profile photo to make your portfolio more personal.';
    }

    // Bio/About section (10 pts)
    $about = $content['about'] ?? '';
    if (!empty($about)) {
        $score += 10;
        // Bio length bonus (5 pts)
        if (strlen($about) > 100) {
            $score += 5;
        } else {
            $suggestions[] = 'Expand your About section to at least 100 characters.';
        }
    } else {
        $suggestions[] = 'Add an About/Bio section to introduce yourself.';
    }

    // Skills (10 pts)
    $skills = $content['skills'] ?? ($user['skills_json'] ? json_decode($user['skills_json'], true) : []);
    if (is_array($skills) && count($skills) >= 3) {
        $score += 10;
    } else {
        $suggestions[] = 'Add at least 3 skills to showcase your expertise.';
    }

    // Projects (15 pts)
    $projects = $content['projects'] ?? [];
    if (is_array($projects) && count($projects) >= 2) {
        $score += 15;
    } else {
        $suggestions[] = 'Add at least 2 projects to demonstrate your work.';
    }

    // Project descriptions (10 pts)
    $hasDescriptions = true;
    foreach ($projects as $p) {
        if (empty($p['description'])) {
            $hasDescriptions = false;
            break;
        }
    }
    if ($hasDescriptions && count($projects) > 0) {
        $score += 10;
    } else if (count($projects) > 0) {
        $suggestions[] = 'Add descriptions to all your projects.';
    }

    // Project links/images (5 pts)
    $hasLinks = false;
    foreach ($projects as $p) {
        if (!empty($p['link']) || !empty($p['image'])) {
            $hasLinks = true;
            break;
        }
    }
    if ($hasLinks) {
        $score += 5;
    } else if (count($projects) > 0) {
        $suggestions[] = 'Add links or images to your projects.';
    }

    // Education (10 pts)
    if (!empty($content['education']) || !empty($user['education'])) {
        $score += 10;
    } else {
        $suggestions[] = 'Add your education background.';
    }

    // Experience (10 pts)
    $experience = $content['experience'] ?? [];
    if (!empty($experience)) {
        $score += 10;
    } else {
        $suggestions[] = 'Add your work experience.';
    }

    // Social links (5 pts)
    $social = $content['social_links'] ?? ($content['social'] ?? []);
    if (empty($social)) {
        $social = $user['social_links_json'] ? json_decode($user['social_links_json'], true) : [];
    }
    if (is_array($social) && count($social) >= 2) {
        $score += 5;
    } else {
        $suggestions[] = 'Add at least 2 social media links (GitHub, LinkedIn, etc.).';
    }

    // Contact info (5 pts)
    if (!empty($user['email']) && (!empty($user['phone']) || !empty($content['contact']))) {
        $score += 5;
    } else {
        $suggestions[] = 'Add your contact information (phone or contact form).';
    }

    // Certifications (5 pts)
    $certs = $content['certifications'] ?? ($content['certificates'] ?? []);
    if (!empty($certs)) {
        $score += 5;
    } else {
        $suggestions[] = 'Add certifications to boost your credibility.';
    }

    return [
        'score' => min($score, 100),
        'suggestions' => $suggestions
    ];
}
?>
