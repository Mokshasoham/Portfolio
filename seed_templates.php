<?php
require_once 'api/config.php';

$templates = [
    ['Cinematic', 'cinematic', 'A premium 3D cinematic template.'],
    ['Bento', 'bento', 'A grid-based bento layout.'],
    ['Corporate', 'corporate', 'Professional business style.'],
    ['Creative', 'creative', 'Bold and experimental.'],
    ['Creator', 'creator', 'For content creators.'],
    ['Cyberpunk', 'cyberpunk', 'Neon-lit futuristic style.'],
    ['Developer', 'developer', 'Clean code-focused layout.'],
    ['Editorial', 'editorial', 'Elegant typography focus.'],
    ['Futuristic', 'futuristic', 'Sleek high-tech design.'],
    ['Geometric', 'geometric', 'Sharp lines and shapes.'],
    ['Minimal', 'minimal', 'Clean and simple.'],
    ['Modern', 'modern', 'The latest design trends.'],
    ['Monochrome', 'monochrome', 'Stylish black and white.'],
    ['Nature', 'nature', 'Organic and earthy tones.'],
    ['NeoBrutalism', 'neobrutalism', 'Raw and bold contrast.'],
    ['Photography', 'photography', 'Visual portfolio for artists.'],
    ['Playful', 'playful', 'Fun and colorful.'],
    ['Professional', 'professional', 'Polished career focus.'],
    ['Retro', 'retro', 'Classic 8-bit aesthetic.'],
    ['Typographic', 'typographic', 'Text-heavy artistic layout.'],
    // New 20
    ['Gradient', 'gradient', 'Vibrant mesh gradients.'],
    ['Dark Minimal', 'dark_minimal', 'Ultra dark, thin lines.'],
    ['Magazine', 'magazine', 'Large serif typography.'],
    ['Software', 'software', 'SaaS style, clean blue.'],
    ['Game', 'game', 'Gaming/Discord aesthetic.'],
    ['Glitch', 'glitch', 'Cyberpunk glitchy effects.'],
    ['Brutalist', 'brutalist', 'Raw grey industrial style.'],
    ['Pastel', 'pastel', 'Soft colors and rounded shapes.'],
    ['Glass', 'glass', 'Heavy glassmorphism style.'],
    ['Terminal', 'terminal', 'Command line interface style.'],
    ['Sketch', 'sketch', 'Hand-drawn notebook feel.'],
    ['Architect', 'architect', 'Structured blueprint feel.'],
    ['Vogue', 'vogue', 'Fashion high-contrast style.'],
    ['Hacker', 'hacker', 'Matrix green terminal style.'],
    ['Neon', 'neon', 'Dark with heavy glowing accents.'],
    ['Material', 'material', 'Google Material Design style.'],
    ['Organic', 'organic', 'Curvy lines and earthy tones.'],
    ['Pop Art', 'pop_art', 'Comic book colors and dots.'],
    ['Industrial', 'industrial', 'Steel and tech feel.'],
    ['Zen', 'zen', 'Japanese minimalist aesthetic.']
];

foreach ($templates as $t) {
    $stmt = $conn->prepare("INSERT IGNORE INTO templates (name, slug, description, is_premium) VALUES (?, ?, ?, 1)");
    $stmt->bind_param("sss", $t[0], $t[1], $t[2]);
    $stmt->execute();
    $stmt->close();
}

echo "Seeded " . count($templates) . " templates into DB.\n";
?>
