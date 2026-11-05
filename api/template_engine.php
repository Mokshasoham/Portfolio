<?php
/**
 * CreativePort — Template Engine
 * Injects user data into templates with smart rendering
 * Supports conditional sections, loops, and safe data binding
 */

class TemplateEngine {
    private $data = [];
    private $sections_enabled = [];

    public function __construct($data = [], $sections = []) {
        $this->data = $data;
        $this->sections_enabled = $sections;
    }

    /**
     * Load and render a template file with user data
     * @param string $template_path Path to template file
     * @param array $data User/portfolio data
     * @param array $sections Sections visibility
     * @return string Rendered HTML
     */
    public static function render($template_path, $data = [], $sections = []) {
        $engine = new self($data, $sections);
        return $engine->process(file_get_contents($template_path));
    }

    /**
     * Main template processing function
     */
    private function process($content) {
        // Remove template syntax markers
        $content = $this->removeComments($content);
        
        // Process conditionals & sections
        $content = $this->processConditionals($content);
        
        // Process loops
        $content = $this->processLoops($content);
        
        // Replace variables
        $content = $this->replaceVariables($content);
        
        // Clean up any remaining template markers
        $content = $this->cleanup($content);
        
        return $content;
    }

    /**
     * Remove template comments
     */
    private function removeComments($content) {
        return preg_replace('/\{\{!--.*?--\}\}/s', '', $content);
    }

    /**
     * Process {{#if_section name}}...{{/if_section}} blocks
     */
    private function processConditionals($content) {
        // Pattern: {{#if_section name}}content{{/if_section}}
        $pattern = '/\{\{#if_section\s+(\w+)\}\}(.*?)\{\{\/if_section\}\}/s';
        
        $content = preg_replace_callback($pattern, function($matches) {
            $section_name = $matches[1];
            $section_content = $matches[2];
            
            // Check if section is enabled and has data
            $is_enabled = isset($this->sections_enabled[$section_name]) ? 
                          $this->sections_enabled[$section_name] : true;
            $has_data = !empty($this->data[$section_name]);
            if (!$has_data && $section_name === 'contact') {
                $has_data = !empty($this->data['email']) || !empty($this->data['phone']) || !empty($this->data['website']);
            }
            if (!$has_data && $section_name === 'about') {
                $has_data = !empty($this->data['bio']);
            }
            
            return ($is_enabled && $has_data) ? $section_content : '';
        }, $content);

        $content = preg_replace_callback('/\{\{#if\s+([\w\.]+)\}\}(.*?)\{\{\/if\}\}/s', function($matches) {
            $value = $this->getNestedValue($matches[1]);
            return !empty($value) ? $matches[2] : '';
        }, $content);
        
        return $content;
    }

    /**
     * Process {{#each array}}...{{/each}} loops
     */
    private function processLoops($content) {
        while (($start = strpos($content, '{{#each ')) !== false) {
            if (!preg_match('/\{\{#each\s+([\w\.]+)\}\}/', $content, $openMatch, PREG_OFFSET_CAPTURE, $start)) {
                break;
            }

            $openStart = $openMatch[0][1];
            $openEnd = $openStart + strlen($openMatch[0][0]);
            $varName = $openMatch[1][0];
            $close = $this->findEachClose($content, $openEnd);

            if ($close === null) {
                break;
            }

            $loopContent = substr($content, $openEnd, $close['start'] - $openEnd);
            $replacement = $this->renderLoop($varName, $loopContent);
            $content = substr($content, 0, $openStart) . $replacement . substr($content, $close['end']);
        }

        return $content;
    }

    private function findEachClose($content, $offset) {
        $depth = 1;
        preg_match_all('/\{\{#each\s+[\w\.]+\}\}|\{\{\/each\}\}/', $content, $matches, PREG_OFFSET_CAPTURE, $offset);

        foreach ($matches[0] as $match) {
            $token = $match[0];
            $pos = $match[1];

            if (strpos($token, '{{#each') === 0) {
                $depth++;
            } else {
                $depth--;
                if ($depth === 0) {
                    return ['start' => $pos, 'end' => $pos + strlen($token)];
                }
            }
        }

        return null;
    }

    private function renderLoop($varName, $loopContent) {
        $array = $this->getNestedValue($varName);
        if (!is_array($array)) {
            return '';
        }

        $output = '';
        foreach ($array as $item) {
            $itemData = is_array($item) ? $item : ['this' => $item];
            $itemData['this'] = is_array($item) ? (reset($item) ?: '') : $item;
            $engine = new self(array_merge($this->data, $itemData), $this->sections_enabled);
            $output .= $engine->process($loopContent);
        }

        return $output;
    }

    /**
     * Replace {{variable}} with values from data array
     */
    private function replaceVariables($content) {
        // Pattern: {{variable}} or {{nested.value}} or {{array.0.field}}
        $pattern = '/\{\{([\w\.]+)\}\}/';
        
        $content = preg_replace_callback($pattern, function($matches) {
            $var_path = $matches[1];
            $value = $this->getNestedValue($var_path);
            
            if ($value === null) {
                return '';
            }
            if (is_array($value)) {
                $value = implode(', ', array_map(function($item) {
                    return is_scalar($item) ? (string)$item : json_encode($item);
                }, $value));
            }
            
            // Don't HTML escape URLs or HTML content
            if (strpos($var_path, 'url') !== false || 
                strpos($var_path, 'link') !== false ||
                strpos($var_path, 'html') !== false) {
                return $value;
            }
            
            return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
        }, $content);
        
        return $content;
    }

    /**
     * Get nested value from data array
     * Supports: field, nested.field, array.0.field
     */
    private function getNestedValue($path) {
        $keys = explode('.', $path);
        $value = $this->data;
        
        foreach ($keys as $key) {
            if (is_array($value) && isset($value[$key])) {
                $value = $value[$key];
            } elseif (is_object($value) && property_exists($value, $key)) {
                $value = $value->$key;
            } else {
                return null;
            }
        }
        
        return $value;
    }

    /**
     * Clean up remaining template markers
     */
    private function cleanup($content) {
        // Remove any leftover {{...}} that wasn't processed
        $content = preg_replace('/\{\{.*?\}\}/s', '', $content);
        
        // Clean extra whitespace
        $content = preg_replace('/\n\s*\n/', "\n", $content);
        
        return $content;
    }

    /**
     * Get demo data for a template
     */
    public static function getDemo($template_name = 'minimal') {
        return [
            'name' => 'Alex Johnson',
            'job_title' => 'Full Stack Developer & Creative Developer',
            'bio' => 'Crafting beautiful, functional digital experiences with code and creativity. Passionate about web technologies, user experience, and pushing creative boundaries. With 5+ years of experience, I help brands and startups build innovative digital products.',
            'avatar' => 'avatar-placeholder', // SVG avatars now embedded in templates
            'email' => 'alex@creativeport.io',
            'phone' => '+1 (555) 123-4567',
            'location' => 'San Francisco, CA',
            'website' => 'https://alexjohnson.dev',
            'current_year' => date('Y'),
            'experience_years' => 5,
            'project_count' => 24,
            'clients' => 15,
            'awards' => 5,
            'about' => 'With a background in both design and development, I bring a unique perspective to every project. I believe great digital products are built at the intersection of beautiful design and solid engineering. My journey started with a passion for building things on the web, and it has evolved into a mission to create experiences that matter.',
            'skills' => [
                'JavaScript/TypeScript',
                'React.js',
                'Node.js',
                'Next.js',
                'Tailwind CSS',
                'MongoDB',
                'PostgreSQL',
                'REST APIs',
                'GraphQL',
                'Web Design',
                'UI/UX',
                'Git/GitHub'
            ],
            'projects' => [
                [
                    'title' => 'E-Commerce Platform',
                    'description' => 'A full-featured e-commerce platform built with Next.js and Stripe integration. Features include product catalog, shopping cart, order management, and admin dashboard.',
                    'image' => 'https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=500&h=300&fit=crop',
                    'tech_stack' => ['Next.js', 'React', 'Tailwind CSS', 'Stripe', 'MongoDB'],
                    'live_link' => 'https://example-shop.dev',
                    'github_link' => 'https://github.com/alexjohnson/ecommerce'
                ],
                [
                    'title' => 'Task Management App',
                    'description' => 'Collaborative task management application with real-time updates, team collaboration features, and smart notifications.',
                    'image' => 'https://images.unsplash.com/photo-1540350881063-2ec96e9b9f6d?w=500&h=300&fit=crop',
                    'tech_stack' => ['React', 'Node.js', 'MongoDB', 'Socket.io'],
                    'live_link' => 'https://tasks-app.dev',
                    'github_link' => 'https://github.com/alexjohnson/tasks'
                ],
                [
                    'title' => 'Portfolio Website',
                    'description' => 'Personal portfolio showcasing my work with smooth animations, dark mode, and responsive design.',
                    'image' => 'https://images.unsplash.com/photo-1561070791-2526d30994b5?w=500&h=300&fit=crop',
                    'tech_stack' => ['Next.js', 'Tailwind', 'Framer Motion', 'MDX'],
                    'live_link' => 'https://alexjohnson.dev',
                    'github_link' => 'https://github.com/alexjohnson/portfolio'
                ]
            ],
            'experience' => [
                [
                    'role' => 'Senior Developer',
                    'company' => 'Tech Innovators Inc',
                    'duration' => 'Jan 2022 - Present',
                    'description' => 'Leading development of customer-facing applications, mentoring junior developers, and architecting scalable solutions.'
                ],
                [
                    'role' => 'Full Stack Developer',
                    'company' => 'Digital Creative Agency',
                    'duration' => 'Jun 2020 - Dec 2021',
                    'description' => 'Built responsive web applications for 20+ clients, implemented design systems, and optimized performance.'
                ],
                [
                    'role' => 'Junior Developer',
                    'company' => 'StartupXYZ',
                    'duration' => 'Jan 2019 - May 2020',
                    'description' => 'Developed features for web application, fixed bugs, and learned modern development practices.'
                ]
            ],
            'certifications' => [
                'AWS Certified Solutions Architect',
                'Google Cloud Associate Cloud Engineer',
                'Advanced JavaScript (Udacity)',
                'Full Stack Development Nanodegree',
                'Web Design Certification'
            ],
            'social_links' => [
                ['platform' => 'github', 'url' => 'https://github.com/alexjohnson'],
                ['platform' => 'linkedin', 'url' => 'https://linkedin.com/in/alexjohnson'],
                ['platform' => 'twitter', 'url' => 'https://twitter.com/alexjohnson'],
                ['platform' => 'dribbble', 'url' => 'https://dribbble.com/alexjohnson']
            ]
        ];
    }
}

// If called directly via POST, render preview
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['action']) && $_GET['action'] === 'preview') {
    header('Content-Type: text/html; charset=utf-8');
    
    $template_name = $_POST['template'] ?? 'minimal';
    $template_file = __DIR__ . '/../templates/' . preg_replace('/[^a-z0-9_-]/', '', $template_name) . '.html';
    
    if (!file_exists($template_file)) {
        die('<h1>Template not found</h1>');
    }
    
    $data = $_POST['data'] ? json_decode($_POST['data'], true) : TemplateEngine::getDemo($template_name);
    $sections = $_POST['sections'] ? json_decode($_POST['sections'], true) : 
               ['about' => true, 'skills' => true, 'projects' => true, 'experience' => true, 
                'certifications' => true, 'contact' => true];
    
    echo TemplateEngine::render($template_file, $data, $sections);
}
?>
