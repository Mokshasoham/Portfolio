-- ============================================================
-- CreativePort — AI-Powered Portfolio Builder
-- Database Setup Script
-- Run: mysql -u root < setup.sql   (or import via phpMyAdmin)
-- ============================================================

CREATE DATABASE IF NOT EXISTS portfolio_db;
USE portfolio_db;

-- ============================================================
-- 1. USERS TABLE (enhanced from existing)
-- ============================================================
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    avatar VARCHAR(255) DEFAULT NULL,
    role VARCHAR(50) DEFAULT 'user',
    phone VARCHAR(30) DEFAULT NULL,
    phone_country VARCHAR(5) DEFAULT NULL,
    birthday DATE DEFAULT NULL,
    location VARCHAR(150) DEFAULT NULL,
    bio TEXT DEFAULT NULL,
    education VARCHAR(255) DEFAULT NULL,
    company VARCHAR(150) DEFAULT NULL,
    website VARCHAR(255) DEFAULT NULL,
    job_title VARCHAR(150) DEFAULT NULL,
    experience VARCHAR(50) DEFAULT NULL,
    skills_json JSON DEFAULT NULL,
    social_links_json JSON DEFAULT NULL,
    target_role VARCHAR(100) DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Bring older installs up to the current user profile schema.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS avatar VARCHAR(255) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS role VARCHAR(50) DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS phone VARCHAR(30) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS phone_country VARCHAR(5) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS birthday DATE DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS location VARCHAR(150) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS bio TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS education VARCHAR(255) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS company VARCHAR(150) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS website VARCHAR(255) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS job_title VARCHAR(150) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS experience VARCHAR(50) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS skills_json JSON DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS social_links_json JSON DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS target_role VARCHAR(100) DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

-- ============================================================
-- 2. TEMPLATES TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(50) NOT NULL UNIQUE,
    description TEXT DEFAULT NULL,
    preview_image VARCHAR(255) DEFAULT NULL,
    category VARCHAR(50) DEFAULT 'general',
    is_premium TINYINT(1) DEFAULT 0,
    config_json JSON DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Seed default templates
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

-- Seed every template view shipped in portfolio/views. Existing rows are preserved.
INSERT IGNORE INTO templates (name, slug, description, category, is_premium) VALUES
('AI Matrix', 'ai_matrix', 'AI-inspired matrix layout for technical portfolios.', 'developer', 1),
('Architect', 'architect', 'Structured architectural layout with clean hierarchy.', 'professional', 1),
('Aurora', 'aurora', 'Luminous aurora-inspired portfolio style.', 'creative', 1),
('Blockchain Dark', 'blockchain_dark', 'Dark Web3 visual system for blockchain builders.', 'developer', 1),
('Blueprint', 'blueprint', 'Blueprint-style technical presentation.', 'professional', 1),
('Brutalist', 'brutalist', 'Raw, bold brutalist visual direction.', 'creative', 1),
('Charcoal', 'charcoal', 'Refined dark charcoal theme.', 'general', 0),
('Code Grid', 'code_grid', 'Grid-based layout for code-heavy portfolios.', 'developer', 1),
('Comic', 'comic', 'Illustrated comic-style portfolio.', 'creative', 1),
('Consulting Clean', 'consulting_clean', 'Sharp consultant-focused business layout.', 'professional', 0),
('Corporate Edge', 'corporate_edge', 'Enterprise style with stronger visual contrast.', 'professional', 1),
('Dark Minimal', 'dark_minimal', 'Minimal layout with a dark color system.', 'general', 0),
('Desert Royal', 'desert_royal', 'Warm premium editorial visual style.', 'creative', 1),
('Editorial Mag', 'editorial_mag', 'High-impact magazine editorial template.', 'creative', 1),
('Finance Pro', 'finance_pro', 'Polished finance and analyst portfolio.', 'professional', 1),
('Game', 'game', 'Game-inspired portfolio interface.', 'developer', 1),
('Gaming HUD', 'gaming_hud', 'Heads-up display aesthetic for gaming profiles.', 'developer', 1),
('Glass', 'glass', 'Transparent glass-style portfolio.', 'general', 1),
('Glass Lux', 'glass_lux', 'Premium glassmorphism portfolio.', 'general', 1),
('Glitch', 'glitch', 'Glitchy high-energy digital layout.', 'developer', 1),
('Gradient', 'gradient', 'Colorful gradient-forward presentation.', 'general', 0),
('Graffiti', 'graffiti', 'Street-art inspired creative portfolio.', 'creative', 1),
('Hacker', 'hacker', 'Dark hacker-style technical template.', 'developer', 1),
('Industrial', 'industrial', 'Industrial monochrome layout for makers.', 'professional', 1),
('Legal Classic', 'legal_classic', 'Traditional legal and professional services layout.', 'professional', 0),
('Magazine', 'magazine', 'Editorial magazine-style portfolio.', 'creative', 1),
('Material', 'material', 'Material-inspired clean card system.', 'general', 0),
('Meme Pop', 'meme_pop', 'Playful pop-culture portfolio style.', 'creative', 1),
('Minimal White', 'minimal_white', 'Bright white minimalist layout.', 'general', 0),
('Neon', 'neon', 'Bright neon visual system.', 'creative', 1),
('Neon Noir', 'neon_noir', 'Dark cinematic neon portfolio.', 'creative', 1),
('Nordic', 'nordic', 'Calm Nordic minimal portfolio.', 'general', 0),
('Organic', 'organic', 'Soft organic shapes and natural layout.', 'general', 0),
('Parchment', 'parchment', 'Classic parchment-inspired presentation.', 'creative', 1),
('Pastel', 'pastel', 'Soft pastel creative portfolio.', 'creative', 0),
('Pixel Arcade', 'pixel_arcade', 'Pixel arcade-inspired portfolio.', 'developer', 1),
('Pop Art', 'pop_art', 'Bold pop-art visual language.', 'creative', 1),
('Retro Future', 'retro_future', 'Retro-futurist interface style.', 'developer', 1),
('Sketch', 'sketch', 'Hand-sketched creative portfolio.', 'creative', 1),
('Software', 'software', 'Software engineer-focused portfolio.', 'developer', 0),
('Startup Pitch', 'startup_pitch', 'Founder and startup pitch-style portfolio.', 'professional', 1),
('Storybook', 'storybook', 'Narrative storybook portfolio layout.', 'creative', 1),
('Techno', 'techno', 'Modern techno-inspired technical layout.', 'developer', 1),
('Terminal', 'terminal', 'Command-line inspired portfolio.', 'developer', 0),
('Terminal Portfolio', 'terminal_portfolio', 'Expanded terminal portfolio view.', 'developer', 1),
('Vaporwave', 'vaporwave', 'Retro vaporwave visual style.', 'creative', 1),
('Vogue', 'vogue', 'Fashion editorial-inspired portfolio.', 'creative', 1),
('Watercolor', 'watercolor', 'Soft watercolor creative layout.', 'creative', 1),
('Zen', 'zen', 'Quiet zen-inspired portfolio.', 'general', 0),
('Zen Japanese', 'zen_japanese', 'Japanese minimalist portfolio style.', 'general', 1);

-- ============================================================
-- 3. PORTFOLIOS TABLE
-- ============================================================
CREATE TABLE IF NOT EXISTS portfolios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    template_id INT DEFAULT NULL,
    title VARCHAR(200) NOT NULL DEFAULT 'My Portfolio',
    slug VARCHAR(100) NOT NULL,
    content_json JSON DEFAULT NULL,
    score INT DEFAULT 0,
    status ENUM('draft', 'published') DEFAULT 'draft',
    is_public TINYINT(1) DEFAULT 1,
    role_type VARCHAR(100) DEFAULT NULL,
    sections_visibility JSON DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_slug (user_id, slug),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (template_id) REFERENCES templates(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 4. PORTFOLIO VIEWS (Analytics)
-- ============================================================
CREATE TABLE IF NOT EXISTS portfolio_views (
    id INT AUTO_INCREMENT PRIMARY KEY,
    portfolio_id INT NOT NULL,
    viewer_ip VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    referrer VARCHAR(500) DEFAULT NULL,
    viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (portfolio_id) REFERENCES portfolios(id) ON DELETE CASCADE,
    INDEX idx_portfolio_viewed (portfolio_id, viewed_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 5. FEEDBACK TABLE (consolidated)
-- ============================================================
CREATE TABLE IF NOT EXISTS feedback (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT DEFAULT NULL,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(150) NOT NULL,
    rating INT DEFAULT NULL,
    feedback_type VARCHAR(50) DEFAULT NULL,
    message TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 6. PASSWORD RESETS
-- ============================================================
CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(150) NOT NULL,
    token VARCHAR(255) NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_token (token),
    INDEX idx_email (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 7. PORTFOLIO VERSIONS
-- ============================================================
CREATE TABLE IF NOT EXISTS portfolio_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    portfolio_id INT NOT NULL,
    version_name VARCHAR(150) NOT NULL,
    content_json JSON DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (portfolio_id) REFERENCES portfolios(id) ON DELETE CASCADE,
    INDEX idx_portfolio_versions (portfolio_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- 8. PORTFOLIO SEO
-- ============================================================
CREATE TABLE IF NOT EXISTS portfolio_seo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    portfolio_id INT NOT NULL UNIQUE,
    meta_title VARCHAR(255) DEFAULT NULL,
    meta_description VARCHAR(500) DEFAULT NULL,
    og_image VARCHAR(255) DEFAULT NULL,
    seo_score INT DEFAULT 0,
    suggestions_json JSON DEFAULT NULL,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (portfolio_id) REFERENCES portfolios(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================
-- Done! All tables created successfully.
-- ============================================================
