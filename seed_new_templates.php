<?php
/**
 * Seed 20 New Premium Templates to Database
 * Run once to add all new templates to templates table
 */
require_once __DIR__ . '/api/config.php';

$newTemplates = [
    ['name' => 'Neon Noir', 'slug' => 'neon_noir', 'description' => 'Cyberpunk aesthetic with glowing neon accents, character animation effects, and custom cursor tracking.', 'category' => 'developer', 'is_premium' => 1],
    ['name' => 'Watercolor', 'slug' => 'watercolor', 'description' => 'Soft pastel portfolio with brush textures, fluid artistic transitions, and serif typography.', 'category' => 'creative', 'is_premium' => 1],
    ['name' => 'Glass Lux', 'slug' => 'glass_lux', 'description' => 'Premium glassmorphism design with gold accents, luxury dark background, and radial glow animations.', 'category' => 'professional', 'is_premium' => 1],
    ['name' => 'Graffiti', 'slug' => 'graffiti', 'description' => 'Street-art inspired bold design with rotated elements, spray textures, and vibrant color palette.', 'category' => 'creative', 'is_premium' => 1],
    ['name' => 'Editorial Magazine', 'slug' => 'editorial_mag', 'description' => 'Magazine-style layout with big typography, grid-based storytelling, and editorial grid system.', 'category' => 'general', 'is_premium' => 1],
    ['name' => 'Corporate Edge', 'slug' => 'corporate_edge', 'description' => 'Clean enterprise dashboard with sharp lines, card-glow effects, and professional subtlety.', 'category' => 'professional', 'is_premium' => 0],
    ['name' => 'Finance Pro', 'slug' => 'finance_pro', 'description' => 'Trust-driven financial design with muted blues/greens, left-border accents, and serious tone.', 'category' => 'professional', 'is_premium' => 1],
    ['name' => 'Legal Classic', 'slug' => 'legal_classic', 'description' => 'Formal authoritative design with serif typography, gold borders, and traditional legal aesthetic.', 'category' => 'professional', 'is_premium' => 1],
    ['name' => 'Startup Pitch', 'slug' => 'startup_pitch', 'description' => 'Modern SaaS landing page vibe with pitch deck format, glassmorphism cards, and indigo/pink gradients.', 'category' => 'general', 'is_premium' => 1],
    ['name' => 'Consulting Clean', 'slug' => 'consulting_clean', 'description' => 'Minimal structured consulting portfolio with maximum whitespace and typography-driven layout.', 'category' => 'professional', 'is_premium' => 0],
    ['name' => 'Terminal Portfolio', 'slug' => 'terminal_portfolio', 'description' => 'CLI-inspired terminal UI with green-on-black aesthetic, scan-line effects, and command output styling.', 'category' => 'developer', 'is_premium' => 1],
    ['name' => 'Code Grid', 'slug' => 'code_grid', 'description' => 'VS Code editor aesthetic with sidebar explorer, syntax highlighting, and code-focused presentation.', 'category' => 'developer', 'is_premium' => 1],
    ['name' => 'AI Matrix', 'slug' => 'ai_matrix', 'description' => 'Matrix-style green-on-black with data streams, canvas-based digital rain effects, and terminal panels.', 'category' => 'developer', 'is_premium' => 1],
    ['name' => 'Blockchain Dark', 'slug' => 'blockchain_dark', 'description' => 'Web3-inspired portfolio with animated blockchain network visualization, cyan/magenta colors, and crypto nodes.', 'category' => 'developer', 'is_premium' => 1],
    ['name' => 'Pixel Arcade', 'slug' => 'pixel_arcade', 'description' => 'Retro pixel UI with 8-bit fonts, arcade-style borders, quest logs, and skill tree organization.', 'category' => 'creative', 'is_premium' => 1],
    ['name' => 'Gaming HUD', 'slug' => 'gaming_hud', 'description' => 'FPS game UI with HUD overlays, stat panels, radar visualization, and futuristic glowing effects.', 'category' => 'creative', 'is_premium' => 1],
    ['name' => 'Meme Pop', 'slug' => 'meme_pop', 'description' => 'Internet culture inspired playful portfolio with animated gradients, card rotations, and emoji integration.', 'category' => 'creative', 'is_premium' => 0],
    ['name' => 'Storybook', 'slug' => 'storybook', 'description' => 'Narrative scroll-based design with book aesthetic, serif typography, chapter-based layout, and timeline.', 'category' => 'creative', 'is_premium' => 1],
    ['name' => 'Zen Japanese', 'slug' => 'zen_japanese', 'description' => 'Minimal calm design with ink brush elements, maximum whitespace, and zen garden aesthetics.', 'category' => 'general', 'is_premium' => 1],
    ['name' => 'Desert Royal', 'slug' => 'desert_royal', 'description' => 'Premium desert aesthetic with warm sand textures, royal gold accents, and luxury gradient backgrounds.', 'category' => 'professional', 'is_premium' => 1],
];

$added = 0;
$skipped = 0;

foreach ($newTemplates as $template) {
    // Check if template already exists
    $checkStmt = $conn->prepare("SELECT id FROM templates WHERE slug = ?");
    $checkStmt->bind_param("s", $template['slug']);
    $checkStmt->execute();
    $checkStmt->store_result();
    
    if ($checkStmt->num_rows > 0) {
        $checkStmt->close();
        $skipped++;
        continue;
    }
    $checkStmt->close();
    
    // Insert template
    $stmt = $conn->prepare("
        INSERT INTO templates (name, slug, description, category, is_premium)
        VALUES (?, ?, ?, ?, ?)
    ");
    $stmt->bind_param("ssssi", 
        $template['name'],
        $template['slug'],
        $template['description'],
        $template['category'],
        $template['is_premium']
    );
    
    if ($stmt->execute()) {
        $added++;
    }
    $stmt->close();
}

echo json_encode([
    'status' => 'success',
    'message' => "Templates seeded. Added: $added, Skipped: $skipped",
    'added' => $added,
    'skipped' => $skipped
]);
$conn->close();
?>
