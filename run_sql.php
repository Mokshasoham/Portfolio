<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die('Connection failed: ' . $conn->connect_error);

$sql = "
USE portfolio_db;
SET FOREIGN_KEY_CHECKS = 0;
TRUNCATE TABLE templates;
SET FOREIGN_KEY_CHECKS = 1;
INSERT INTO templates (name, slug, description, category, is_premium) VALUES
('Cinematic 3D', 'cinematic', 'Immersive 3D environment with particle effects and glowing cursors.', 'creative', 1),
('Minimalist', 'minimal', 'Clean, elegant design with lots of whitespace and refined typography.', 'general', 0),
('Creative Director', 'creative', 'Bold asymmetric layout with massive typography for designers.', 'creative', 1),
('Terminal Coder', 'developer', 'Hacker aesthetic, dark mode, code-syntax styling for developers.', 'developer', 0),
('Modern Glass', 'modern', 'Sleek glassmorphism, soft gradients, and rounded cards.', 'general', 1),
('Neo Brutalism', 'neobrutalism', 'Bold black borders, harsh shadows, and vibrant contrasting colors.', 'creative', 1),
('Visual Creator', 'creator', 'Full-screen visual hero with masonry grid layouts for visual work.', 'creative', 1),
('Professional CV', 'professional', 'Clean, structured palette designed like a modern digital resume.', 'professional', 0),
('Cyberpunk', 'cyberpunk', 'Neon greens and pinks, glitch text effects, and ultra-dark backgrounds.', 'developer', 1),
('Bento Grid', 'bento', 'Apple-style bento grid layout with highly visual interactive widgets.', 'general', 1),
('Retro 8-Bit', 'retro', 'Nostalgic 8-bit style, pixel fonts, and classic arcade color palettes.', 'developer', 1),
('Corporate Enterprise', 'corporate', 'Ultra-clean, trustworthy enterprise style using gray and navy tones.', 'professional', 0),
('Photography Dark', 'photography', 'Dark theme, massive full-screen images, and ultra-minimal text.', 'creative', 1),
('Playful Pastel', 'playful', 'Pastel colors, rounded bubbly fonts, and floating abstract shapes.', 'creative', 0),
('Monochrome Focus', 'monochrome', 'Strictly single accent color scaled beautifully across the UI.', 'general', 0),
('Editorial Magazine', 'editorial', 'Magazine style, serif fonts, drop caps, and multi-column text.', 'general', 1),
('Sci-Fi Futuristic', 'futuristic', 'Sci-fi inspired, hexagonal elements, and glowing neon borders.', 'developer', 1),
('Organic Nature', 'nature', 'Earth tones, green/brown palettes, and soft organic shape dividers.', 'general', 0),
('Geometric Sharp', 'geometric', 'Sharp edges, overlapping triangles and squares with high contrast.', 'creative', 1),
('Typographic Heavy', 'typographic', 'Text is the primary design element featuring oversized fonts and marquees.', 'creative', 1);
";

if ($conn->multi_query($sql)) {
    do {
        if ($result = $conn->store_result()) {
            $result->free();
        }
    } while ($conn->next_result());
    echo 'Templates updated successfully.';
} else {
    echo 'Error: ' . $conn->error;
}
$conn->close();
?>
