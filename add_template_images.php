<?php
/**
 * Add preview images to new templates
 */
require_once __DIR__ . '/api/config.php';

$templateImages = [
    'neon_noir' => 'https://picsum.photos/seed/neon_noir/600/400',
    'watercolor' => 'https://picsum.photos/seed/watercolor/600/400',
    'glass_lux' => 'https://picsum.photos/seed/glass_lux/600/400',
    'graffiti' => 'https://picsum.photos/seed/graffiti/600/400',
    'editorial_mag' => 'https://picsum.photos/seed/editorial_mag/600/400',
    'corporate_edge' => 'https://picsum.photos/seed/corporate_edge/600/400',
    'finance_pro' => 'https://picsum.photos/seed/finance_pro/600/400',
    'legal_classic' => 'https://picsum.photos/seed/legal_classic/600/400',
    'startup_pitch' => 'https://picsum.photos/seed/startup_pitch/600/400',
    'consulting_clean' => 'https://picsum.photos/seed/consulting_clean/600/400',
    'terminal_portfolio' => 'https://picsum.photos/seed/terminal_portfolio/600/400',
    'code_grid' => 'https://picsum.photos/seed/code_grid/600/400',
    'ai_matrix' => 'https://picsum.photos/seed/ai_matrix/600/400',
    'blockchain_dark' => 'https://picsum.photos/seed/blockchain_dark/600/400',
    'pixel_arcade' => 'https://picsum.photos/seed/pixel_arcade/600/400',
    'gaming_hud' => 'https://picsum.photos/seed/gaming_hud/600/400',
    'meme_pop' => 'https://picsum.photos/seed/meme_pop/600/400',
    'storybook' => 'https://picsum.photos/seed/storybook/600/400',
    'zen_japanese' => 'https://picsum.photos/seed/zen_japanese/600/400',
    'desert_royal' => 'https://picsum.photos/seed/desert_royal/600/400',
];

$updated = 0;

foreach ($templateImages as $slug => $imageUrl) {
    try {
        $stmt = $conn->prepare("UPDATE templates SET preview_image = ? WHERE slug = ?");
        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }
        $stmt->bind_param("ss", $imageUrl, $slug);
        if ($stmt->execute()) {
            $updated++;
        }
        $stmt->close();
    } catch (Exception $e) {
        error_log("Error updating $slug: " . $e->getMessage());
    }
}

echo json_encode([
    'status' => 'success',
    'message' => "Preview images added to $updated templates",
    'updated' => $updated
]);
if ($conn) $conn->close();
?>
