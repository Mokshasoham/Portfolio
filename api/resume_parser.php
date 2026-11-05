<?php
/**
 * CreativePort — Resume Parser API (PHP-only, no Composer)
 * Extracts text from uploaded PDF/TXT files using basic parsing.
 * For better results, set AI_PROVIDER to 'openai' or 'gemini' in config.php
 */
require_once __DIR__ . '/config.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
$authUser = requireAuth();

// Handle file upload
$uploadResult = handleFileUpload('resume', RESUME_DIR, MAX_RESUME_SIZE, [
    'application/pdf',
    'text/plain',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
]);

if (isset($uploadResult['error'])) {
    sendError($uploadResult['error']);
}

$filePath = __DIR__ . '/../' . $uploadResult['path'];
$ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

$rawText = '';

// ─── Extract text based on file type ───────────────────────
if ($ext === 'txt') {
    $rawText = file_get_contents($filePath);
} elseif ($ext === 'pdf') {
    $rawText = extractTextFromPDF($filePath);
} else {
    // For DOC/DOCX, try basic extraction
    $rawText = extractTextFromDoc($filePath);
}

if (empty(trim($rawText))) {
    sendError('Could not extract text from the uploaded file. Please try a TXT or different PDF file.');
}

// ─── Parse extracted text ──────────────────────────────────
$parsed = parseResumeText($rawText);

sendSuccess([
    'parsed' => $parsed,
    'raw_text_preview' => substr($rawText, 0, 500),
    'file_path' => $uploadResult['path']
], 'Resume parsed successfully.');

// ═══════════════════════════════════════════════════════════
// EXTRACTION FUNCTIONS
// ═══════════════════════════════════════════════════════════

/**
 * Basic PDF text extraction without external libraries
 */
function extractTextFromPDF($filePath) {
    $content = file_get_contents($filePath);
    $text = '';

    // Method 1: Extract text between BT and ET markers
    if (preg_match_all('/BT\s*(.*?)\s*ET/s', $content, $matches)) {
        foreach ($matches[1] as $block) {
            // Extract text in parentheses (literal strings)
            if (preg_match_all('/\((.*?)\)/', $block, $textMatches)) {
                $text .= implode(' ', $textMatches[1]) . "\n";
            }
            // Extract hex strings
            if (preg_match_all('/<([0-9A-Fa-f]+)>/', $block, $hexMatches)) {
                foreach ($hexMatches[1] as $hex) {
                    if (strlen($hex) % 2 === 0) {
                        $text .= @hex2bin($hex) . ' ';
                    }
                }
            }
        }
    }

    // Method 2: Try stream-based extraction if Method 1 fails
    if (strlen(trim($text)) < 50) {
        if (preg_match_all('/stream\s*(.*?)\s*endstream/s', $content, $streams)) {
            foreach ($streams[1] as $stream) {
                $decoded = @gzuncompress($stream);
                if ($decoded) {
                    if (preg_match_all('/\((.*?)\)/', $decoded, $textMatches)) {
                        $text .= implode(' ', $textMatches[1]) . "\n";
                    }
                }
            }
        }
    }

    // Clean up
    $text = preg_replace('/[^\x20-\x7E\n]/', '', $text);
    $text = preg_replace('/\n{3,}/', "\n\n", $text);

    return trim($text);
}

/**
 * Basic DOC/DOCX text extraction
 */
function extractTextFromDoc($filePath) {
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));

    if ($ext === 'docx') {
        // DOCX is a ZIP file containing XML
        $zip = new ZipArchive();
        if ($zip->open($filePath) === true) {
            $content = $zip->getFromName('word/document.xml');
            $zip->close();
            if ($content) {
                $text = strip_tags($content);
                return preg_replace('/\s+/', ' ', $text);
            }
        }
    }

    // Fallback: try to read as plain text
    $content = file_get_contents($filePath);
    $text = preg_replace('/[^\x20-\x7E\n]/', '', $content);
    return trim($text);
}

// ═══════════════════════════════════════════════════════════
// PARSING FUNCTIONS
// ═══════════════════════════════════════════════════════════

function parseResumeText($text) {
    $result = [
        'name' => '',
        'email' => '',
        'phone' => '',
        'location' => '',
        'education' => [],
        'skills' => [],
        'experience' => [],
        'projects' => [],
        'summary' => ''
    ];

    $lines = explode("\n", $text);
    $lines = array_map('trim', $lines);
    $lines = array_filter($lines);

    // ─── Extract email ─────────────────────────────────────
    if (preg_match('/[\w.+-]+@[\w-]+\.[\w.]+/', $text, $emailMatch)) {
        $result['email'] = $emailMatch[0];
    }

    // ─── Extract phone ─────────────────────────────────────
    if (preg_match('/(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/', $text, $phoneMatch)) {
        $result['phone'] = $phoneMatch[0];
    }

    // ─── Extract name (usually first significant line) ─────
    foreach ($lines as $line) {
        $line = trim($line);
        if (strlen($line) > 2 && strlen($line) < 60 && !strpos($line, '@') && !preg_match('/^\d/', $line)) {
            $result['name'] = $line;
            break;
        }
    }

    // ─── Extract skills ────────────────────────────────────
    $skillKeywords = ['html', 'css', 'javascript', 'python', 'java', 'react', 'node', 'angular', 'vue',
        'php', 'mysql', 'mongodb', 'postgresql', 'docker', 'aws', 'git', 'typescript', 'c++', 'c#',
        'ruby', 'swift', 'kotlin', 'flutter', 'django', 'flask', 'spring', 'express', 'laravel',
        'figma', 'photoshop', 'illustrator', 'tailwind', 'bootstrap', 'sass', 'redux', 'graphql',
        'rest api', 'firebase', 'linux', 'jenkins', 'kubernetes', 'terraform', 'machine learning',
        'deep learning', 'tensorflow', 'pytorch', 'pandas', 'numpy', 'sql', 'nosql', 'redis',
        'elasticsearch', 'rabbitmq', 'kafka', 'microservices', 'agile', 'scrum', 'jira'];

    $textLower = strtolower($text);
    foreach ($skillKeywords as $skill) {
        if (strpos($textLower, strtolower($skill)) !== false) {
            $result['skills'][] = ucwords($skill);
        }
    }
    $result['skills'] = array_unique($result['skills']);
    $result['skills'] = array_values($result['skills']);

    // ─── Section-based extraction ──────────────────────────
    $currentSection = '';
    $sectionContent = [];

    foreach ($lines as $line) {
        $lineLower = strtolower($line);

        // Detect section headers
        if (preg_match('/^(education|academic|qualification)/i', $lineLower)) {
            $currentSection = 'education';
            continue;
        } elseif (preg_match('/^(experience|work|employment|professional)/i', $lineLower)) {
            $currentSection = 'experience';
            continue;
        } elseif (preg_match('/^(project|portfolio)/i', $lineLower)) {
            $currentSection = 'projects';
            continue;
        } elseif (preg_match('/^(skill|technical|competenc|expertise)/i', $lineLower)) {
            $currentSection = 'skills_section';
            continue;
        } elseif (preg_match('/^(summary|objective|profile|about)/i', $lineLower)) {
            $currentSection = 'summary';
            continue;
        }

        if ($currentSection && !empty($line)) {
            $sectionContent[$currentSection][] = $line;
        }
    }

    // Map section content to result
    if (!empty($sectionContent['education'])) {
        $result['education'] = array_slice($sectionContent['education'], 0, 5);
    }
    if (!empty($sectionContent['experience'])) {
        $result['experience'] = array_slice($sectionContent['experience'], 0, 10);
    }
    if (!empty($sectionContent['projects'])) {
        $result['projects'] = array_slice($sectionContent['projects'], 0, 10);
    }
    if (!empty($sectionContent['summary'])) {
        $result['summary'] = implode(' ', array_slice($sectionContent['summary'], 0, 3));
    }

    return $result;
}

$conn->close();
?>
