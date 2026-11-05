<?php
/**
 * CreativePort — System Verification & Testing Script
 * Tests all components, database, API endpoints, and generates sample data
 */

ini_set('display_errors', 1);
error_reporting(E_ALL);

// ─── Capture output ───────────────────────────────────────
class TestLogger {
    public $tests = [];
    public $passed = 0;
    public $failed = 0;

    public function test($name, $condition, $details = '') {
        $status = $condition ? 'PASS' : 'FAIL';
        $symbol = $condition ? '✓' : '✗';
        $this->tests[] = compact('name', 'status', 'details');
        if ($condition) $this->passed++; else $this->failed++;
        echo "[$symbol] $name" . ($details ? " — $details" : "") . "\n";
    }

    public function section($title) {
        echo "\n" . str_repeat("─", 60) . "\n";
        echo "  $title\n";
        echo str_repeat("─", 60) . "\n";
    }

    public function summary() {
        echo "\n" . str_repeat("═", 60) . "\n";
        echo "  OVERALL RESULTS\n";
        echo str_repeat("═", 60) . "\n";
        echo "Passed: {$this->passed} | Failed: {$this->failed}\n";
        echo "Success Rate: " . ($this->passed + $this->failed > 0 
            ? round(100 * $this->passed / ($this->passed + $this->failed), 1)
            : 0) . "%\n";
    }
}

$log = new TestLogger();

// ═══════════════════════════════════════════════════════════
// 1. SYSTEM REQUIREMENTS
// ═══════════════════════════════════════════════════════════
$log->section("1. SYSTEM REQUIREMENTS");

$log->test("PHP Version >= 7.4", version_compare(PHP_VERSION, '7.4.0', '>='), PHP_VERSION);
$log->test("MySQLi Extension", extension_loaded('mysqli'), extension_loaded('mysqli') ? 'Loaded' : 'Missing');
$log->test("cURL Extension", extension_loaded('curl'), extension_loaded('curl') ? 'Loaded' : 'Missing');
$log->test("JSON Extension", extension_loaded('json'), extension_loaded('json') ? 'Loaded' : 'Missing');

// ─── Check writable directories ───────────────────────────
$log->section("2. DIRECTORY & FILE PERMISSIONS");

$dirs_to_check = [
    'uploads' => __DIR__ . '/../uploads',
    'uploads/resumes' => __DIR__ . '/../uploads/resumes',
    'uploads/avatars' => __DIR__ . '/../uploads/avatars',
    'uploads/projects' => __DIR__ . '/../uploads/projects',
];

foreach ($dirs_to_check as $name => $path) {
    $exists = is_dir($path);
    if ($exists) {
        $writable = is_writable($path);
        $log->test("$name exists", true, $path);
        $log->test("$name writable", $writable, $writable ? 'Yes' : 'No');
    } else {
        $log->test("$name exists", false, "Creating directory...");
        @mkdir($path, 0755, true);
        $log->test("$name created", is_dir($path), $path);
    }
}

// ─── Check templates ──────────────────────────────────────
$log->section("3. TEMPLATE FILES");

$templates = ['minimal.html', 'modern.html', 'creative.html', 'developer.html'];
$template_dir = __DIR__ . '/../templates';

foreach ($templates as $tpl) {
    $file = "$template_dir/$tpl";
    $exists = file_exists($file);
    $size = $exists ? filesize($file) : 0;
    $log->test("Template: $tpl", $exists, "$size bytes");
}

// ═══════════════════════════════════════════════════════════
// 2. DATABASE TESTS
// ═══════════════════════════════════════════════════════════
$log->section("4. DATABASE CONNECTION & SCHEMA");

define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'portfolio_db');

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
$log->test("Database Connection", !$conn->connect_error, 
    $conn->connect_error ? $conn->connect_error : 'Connected');

if (!$conn->connect_error) {
    $conn->set_charset('utf8mb4');

    // Check tables
    $tables = ['users', 'templates', 'portfolios', 'portfolio_views', 'feedback', 'password_resets'];
    foreach ($tables as $tbl) {
        $result = $conn->query("SHOW TABLES LIKE '$tbl'");
        $log->test("Table: $tbl", $result && $result->num_rows > 0);
    }

    // Check template records
    $log->section("5. DATABASE SAMPLE DATA");
    $result = $conn->query("SELECT COUNT(*) as cnt FROM templates");
    $row = $result->fetch_assoc();
    $log->test("Templates seeded", $row['cnt'] > 0, "{$row['cnt']} templates found");

    // Count users
    $result = $conn->query("SELECT COUNT(*) as cnt FROM users");
    $row = $result->fetch_assoc();
    $log->test("Users table", true, "{$row['cnt']} users");

    // Count portfolios
    $result = $conn->query("SELECT COUNT(*) as cnt FROM portfolios");
    $row = $result->fetch_assoc();
    $log->test("Portfolios table", true, "{$row['cnt']} portfolios");
}

// ═══════════════════════════════════════════════════════════
// 3. INCLUDE & TEST CORE COMPONENTS
// ═══════════════════════════════════════════════════════════
$log->section("6. CORE COMPONENTS");

// Load config
$config_file = __DIR__ . '/config.php';
$log->test("Config file exists", file_exists($config_file));

// Load template engine
$engine_file = __DIR__ . '/template_engine.php';
$log->test("Template engine exists", file_exists($engine_file));
if (file_exists($engine_file)) {
    include_once $engine_file;
    $has_class = class_exists('TemplateEngine');
    $log->test("TemplateEngine class", $has_class);

    if ($has_class && method_exists('TemplateEngine', 'getDemo')) {
        $demo = TemplateEngine::getDemo('minimal');
        $log->test("Demo data generation", !empty($demo) && isset($demo['name']), 
            isset($demo['name']) ? "Name: {$demo['name']}" : 'Failed');
    }
}

// Test parsers
$parser_file = __DIR__ . '/utils/resume_parser.php';
$log->test("Resume parser exists", file_exists($parser_file));
$pdf_parser = __DIR__ . '/utils/pdf_parser.php';
$log->test("PDF parser exists", file_exists($pdf_parser));
$doc_parser = __DIR__ . '/utils/doc_parser.php';
$log->test("DOC parser exists", file_exists($doc_parser));

// ═══════════════════════════════════════════════════════════
// 4. API ENDPOINTS TEST
// ═══════════════════════════════════════════════════════════
$log->section("7. API ENDPOINT AVAILABILITY");

$api_files = [
    'portfolio_generator.php' => 'Portfolio Generator',
    'template_engine.php' => 'Template Engine',
    'auth.php' => 'Authentication',
    'profile.php' => 'Profile',
    'ai.php' => 'AI Services (optional)',
];

foreach ($api_files as $file => $label) {
    $path = __DIR__ . '/' . $file;
    $exists = file_exists($path);
    $log->test("API: $label ($file)", $exists);
}

// ═══════════════════════════════════════════════════════════
// 5. FRONTEND FILES TEST
// ═══════════════════════════════════════════════════════════
$log->section("8. FRONTEND FILES");

$frontend_files = [
    'js/portfolio_generator.js' => 'Portfolio JS',
    'css/portfolio_generator.css' => 'Portfolio CSS',
    'create.html' => 'Create Page',
    'index.html' => 'Home Page',
];

foreach ($frontend_files as $file => $label) {
    $path = __DIR__ . '/../' . $file;
    $exists = file_exists($path);
    $size = $exists ? filesize($path) : 0;
    $log->test("Frontend: $label", $exists, "$size bytes");
}

// ═══════════════════════════════════════════════════════════
// 6. CREATE TEST DATA
// ═══════════════════════════════════════════════════════════
$log->section("9. TEST DATA SETUP");

if (!$conn->connect_error) {
    // Create test user if not exists
    $test_email = 'testuser@example.com';
    $test_pass = password_hash('Test@1234', PASSWORD_BCRYPT);
    
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $test_email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        $test_name = 'Test User';
        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $test_name, $test_email, $test_pass);
        $success = $stmt->execute();
        $log->test("Test user created", $success, $test_email);
    } else {
        $log->test("Test user exists", true, $test_email);
    }

    // Create test resume file
    $resume_content = <<<'RESUME'
John Developer
john.dev@example.com
(555) 123-4567
San Francisco, CA

PROFESSIONAL SUMMARY
Experienced full-stack developer with 5+ years of expertise in PHP, JavaScript, and MySQL.
Passionate about creating innovative web solutions and mentoring junior developers.

SKILLS
PHP, JavaScript, MySQL, HTML5, CSS3, REST APIs, React, Vue.js, Git, Docker, AWS

EXPERIENCE
Senior Developer | Tech Corp | 2023 - Present
- Led development of customer portal (PHP, React)
- Optimized database queries reducing load time by 40%
- Mentored 3 junior developers

Full Stack Developer | Web Solutions LLC | 2020 - 2023
- Built 10+ client websites using PHP and JavaScript
- Implemented automated testing with Jest and PHPUnit
- Managed MySQL databases for 50+ projects

EDUCATION
Bachelor of Computer Science | State University | 2020

CERTIFICATIONS
AWS Certified Solutions Architect
Google Cloud Professional Data Engineer
RESUME;

    $resume_file = __DIR__ . '/../uploads/resumes/test_sample.txt';
    $written = file_put_contents($resume_file, $resume_content);
    $log->test("Test resume file", $written !== false, $written . ' bytes');
}

// ═══════════════════════════════════════════════════════════
// 7. SUMMARY
// ═══════════════════════════════════════════════════════════
$log->summary();

// ─── Output details ───────────────────────────────────────
echo "\n" . str_repeat("─", 60) . "\n";
echo "TEST DETAILS\n";
echo str_repeat("─", 60) . "\n";

foreach ($log->tests as $test) {
    if ($test['status'] === 'FAIL') {
        echo "[{$test['status']}] {$test['name']} — {$test['details']}\n";
    }
}

// ─── Recommendations ──────────────────────────────────────
echo "\n" . str_repeat("─", 60) . "\n";
echo "NEXT STEPS\n";
echo str_repeat("─", 60) . "\n";
echo "1. Visit http://localhost/portifolio/create.html to test the generator\n";
echo "2. Upload the test resume file: uploads/resumes/test_sample.txt\n";
echo "3. Select a template and generate a portfolio\n";
echo "4. View the created portfolio at http://localhost/portfolio/index.php?slug=...\n";
echo "5. Check database for created records\n";

if ($conn && !$conn->connect_error) {
    $conn->close();
}

echo "\nTest complete! " . ($log->failed === 0 ? "✓ All systems operational!" : "⚠ Some items need attention.") . "\n";
