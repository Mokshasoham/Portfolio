<?php
/**
 * SEO Optimization & Metadata Management
 * Generate meta tags, structured data, and SEO suggestions
 */

require_once 'config.php';

class SEOOptimizer {
    private static function currentUrl() {
        $scheme = $_SERVER['REQUEST_SCHEME'] ?? ((!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http');
        $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        return $scheme . '://' . $host . $uri;
    }

    private static function portfolioData($portfolio) {
        $data = json_decode($portfolio['content_json'] ?? '{}', true);
        return is_array($data) ? $data : [];
    }
    
    /**
     * Generate Open Graph meta tags
     */
    public static function generateOGTags($portfolio) {
        $data = self::portfolioData($portfolio);
        $description = $data['about'] ?? $data['bio'] ?? 'My portfolio';
        
        $og_tags = [
            'og:title' => $data['name'] ?? 'Portfolio',
            'og:description' => substr($description, 0, 160),
            'og:type' => 'website',
            'og:image' => $data['avatar'] ?? '/images/default-avatar.png',
            'og:url' => self::currentUrl()
        ];
        
        $html = '';
        foreach ($og_tags as $property => $content) {
            $html .= '<meta property="' . htmlspecialchars($property) . '" content="' . htmlspecialchars($content) . '">' . "\n";
        }
        
        return $html;
    }
    
    /**
     * Generate Twitter Card meta tags
     */
    public static function generateTwitterTags($portfolio) {
        $data = self::portfolioData($portfolio);
        $description = $data['about'] ?? $data['bio'] ?? 'My portfolio';
        
        $twitter_tags = [
            'twitter:card' => 'summary_large_image',
            'twitter:title' => $data['name'] ?? 'Portfolio',
            'twitter:description' => substr($description, 0, 200),
            'twitter:image' => $data['avatar'] ?? '/images/default-avatar.png'
        ];
        
        $html = '';
        foreach ($twitter_tags as $name => $content) {
            $html .= '<meta name="' . htmlspecialchars($name) . '" content="' . htmlspecialchars($content) . '">' . "\n";
        }
        
        return $html;
    }
    
    /**
     * Generate JSON-LD structured data
     */
    public static function generateStructuredData($portfolio) {
        $data = self::portfolioData($portfolio);
        $contact = $data['contact'] ?? [];
        
        $structured_data = [
            '@context' => 'https://schema.org',
            '@type' => 'Person',
            'name' => $data['name'] ?? 'Portfolio',
            'url' => self::currentUrl(),
            'email' => $contact['email'] ?? $data['email'] ?? '',
            'telephone' => $contact['phone'] ?? $data['phone'] ?? '',
            'jobTitle' => $data['target_role'] ?? $data['job_title'] ?? '',
            'description' => $data['about'] ?? $data['bio'] ?? '',
            'image' => $data['avatar'] ?? '',
            'sameAs' => []
        ];
        
        // Add social profiles
        if (!empty($data['social_links'])) {
            $structured_data['sameAs'] = $data['social_links'];
        }
        
        // Add projects/portfolio items
        if (!empty($data['projects'])) {
            $structured_data['workExample'] = array_slice($data['projects'], 0, 5);
        }
        
        return '<script type="application/ld+json">' . json_encode($structured_data, JSON_PRETTY_PRINT) . '</script>';
    }
    
    /**
     * Generate SEO suggestions
     */
    public static function generateSEOSuggestions($portfolio) {
        $data = self::portfolioData($portfolio);
        $contact = $data['contact'] ?? [];
        $suggestions = [];
        $score = 100;
        
        // Check name
        if (empty($data['name'])) {
            $suggestions[] = ['issue' => 'Missing name', 'priority' => 'high'];
            $score -= 15;
        }
        
        // Check bio/description
        $bio = $data['about'] ?? $data['bio'] ?? '';
        if (empty($bio) || strlen($bio) < 50) {
            $suggestions[] = ['issue' => 'Short or missing biography (aim for 50+ characters)', 'priority' => 'high'];
            $score -= 15;
        }
        
        // Check job title
        if (empty($data['target_role']) && empty($data['job_title'])) {
            $suggestions[] = ['issue' => 'Missing job title (helps with search visibility)', 'priority' => 'medium'];
            $score -= 10;
        }
        
        // Check email
        if (empty($contact['email']) && empty($data['email'])) {
            $suggestions[] = ['issue' => 'Missing email address', 'priority' => 'medium'];
            $score -= 10;
        }
        
        // Check projects
        if (empty($data['projects']) || count($data['projects']) < 3) {
            $suggestions[] = ['issue' => 'Add at least 3 projects for better portfolio', 'priority' => 'medium'];
            $score -= 10;
        }
        
        // Check skills
        if (empty($data['skills']) || count($data['skills']) < 5) {
            $suggestions[] = ['issue' => 'Add at least 5 skills', 'priority' => 'low'];
            $score -= 5;
        }
        
        // Check social links
        if (empty($data['social_links']) || count($data['social_links']) < 2) {
            $suggestions[] = ['issue' => 'Add social media links for better engagement', 'priority' => 'low'];
            $score -= 5;
        }
        
        return [
            'score' => max(0, $score),
            'suggestions' => $suggestions,
            'grade' => $score >= 90 ? 'A' : ($score >= 80 ? 'B' : ($score >= 70 ? 'C' : 'D'))
        ];
    }
    
    /**
     * Generate meta description
     */
    public static function generateMetaDescription($portfolio) {
        $data = self::portfolioData($portfolio);
        
        // Use bio if available, otherwise create from name and job title
        if (!empty($data['about']) || !empty($data['bio'])) {
            $description = $data['about'] ?? $data['bio'];
        } else {
            $description = ($data['name'] ?? '') . ' - ' . ($data['target_role'] ?? $data['job_title'] ?? 'Portfolio');
        }
        
        // Trim to 160 characters (Google's standard)
        return substr($description, 0, 160);
    }
}

// API Endpoint
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action'])) {
    $action = $_GET['action'];
    $portfolio_id = intval($_GET['portfolio_id'] ?? 0);
    
    if ($portfolio_id <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid portfolio ID']);
        exit;
    }
    
    // Get portfolio
    $stmt = $GLOBALS['conn']->prepare("SELECT * FROM portfolios WHERE id = ?");
    $stmt->bind_param("i", $portfolio_id);
    $stmt->execute();
    $portfolio = $stmt->get_result()->fetch_assoc();
    
    if (!$portfolio) {
        http_response_code(404);
        echo json_encode(['success' => false, 'error' => 'Portfolio not found']);
        exit;
    }
    
    header('Content-Type: application/json');
    
    switch ($action) {
        case 'get_og_tags':
            echo json_encode([
                'success' => true,
                'html' => SEOOptimizer::generateOGTags($portfolio)
            ]);
            break;
            
        case 'get_twitter_tags':
            echo json_encode([
                'success' => true,
                'html' => SEOOptimizer::generateTwitterTags($portfolio)
            ]);
            break;
            
        case 'get_structured_data':
            echo json_encode([
                'success' => true,
                'html' => SEOOptimizer::generateStructuredData($portfolio)
            ]);
            break;
            
        case 'get_seo_score':
            echo json_encode([
                'success' => true,
                'data' => SEOOptimizer::generateSEOSuggestions($portfolio)
            ]);
            break;
            
        case 'get_meta_description':
            echo json_encode([
                'success' => true,
                'description' => SEOOptimizer::generateMetaDescription($portfolio)
            ]);
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Unknown action']);
    }
}
?>
