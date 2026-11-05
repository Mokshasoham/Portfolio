<?php
/**
 * Create Missing Database Tables for New Features
 */

require_once 'config.php';

echo "Creating missing tables for premium features...\n";

// Create portfolio_versions table if not exists
$sql_versions = "
CREATE TABLE IF NOT EXISTS portfolio_versions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    portfolio_id INT NOT NULL,
    version_name VARCHAR(100) NOT NULL,
    content_json LONGTEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (portfolio_id) REFERENCES portfolios(id) ON DELETE CASCADE,
    KEY idx_portfolio (portfolio_id),
    KEY idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
";

if ($conn->query($sql_versions)) {
    echo "[✓] portfolio_versions table created/verified\n";
} else {
    echo "[✗] Error with portfolio_versions: " . $conn->error . "\n";
}

// Add SEO columns to portfolios table if they don't exist
$check_seo = "ALTER TABLE portfolios ADD COLUMN seo_score INT DEFAULT 0";
try {
    if ($conn->query($check_seo)) {
        echo "[✓] Added seo_score column to portfolios\n";
    }
} catch (Exception $e) {
    echo "[ℹ] seo_score column may already exist\n";
}

// Create portfolio_seo table for storing SEO suggestions
$sql_seo = "
CREATE TABLE IF NOT EXISTS portfolio_seo (
    id INT AUTO_INCREMENT PRIMARY KEY,
    portfolio_id INT NOT NULL UNIQUE,
    seo_score INT DEFAULT 100,
    last_checked TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    suggestions_json JSON DEFAULT NULL,
    FOREIGN KEY (portfolio_id) REFERENCES portfolios(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
";

if ($conn->query($sql_seo)) {
    echo "[✓] portfolio_seo table created/verified\n";
} else {
    echo "[✗] Error with portfolio_seo: " . $conn->error . "\n";
}

echo "\n✅ Database schema updated successfully!\n";
?>
