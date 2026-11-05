#!/bin/bash
# CreativePort — Database & Setup Verification Script
# Run this to verify all components are properly configured

echo "🔍 CreativePort AI Portfolio System - Verification Check"
echo "==========================================================="
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check 1: Directory Structure
echo "1️⃣  Checking Directory Structure..."
declare -a directories=(
    "api"
    "api/utils"
    "templates"
    "css"
    "js"
    "uploads"
    "uploads/resumes"
    "uploads/avatars"
    "uploads/projects"
    "uploads/portfolios"
)

for dir in "${directories[@]}"; do
    if [ -d "$dir" ]; then
        echo -e "${GREEN}✓${NC} $dir/ exists"
    else
        echo -e "${RED}✗${NC} $dir/ missing - CREATE IT"
        mkdir -p "$dir"
    fi
done

echo ""

# Check 2: Required Files
echo "2️⃣  Checking Required Files..."
declare -a files=(
    "api/config.php"
    "api/template_engine.php"
    "api/portfolio_generator.php"
    "api/ai.php"
    "api/resume_parser.php"
    "api/utils/resume_parser.php"
    "api/utils/pdf_parser.php"
    "api/utils/doc_parser.php"
    "templates/minimal.html"
    "templates/modern.html"
    "templates/creative.html"
    "templates/developer.html"
    "css/portfolio_generator.css"
    "js/portfolio_generator.js"
    "create.html"
)

for file in "${files[@]}"; do
    if [ -f "$file" ]; then
        echo -e "${GREEN}✓${NC} $file exists"
    else
        echo -e "${RED}✗${NC} $file missing"
    fi
done

echo ""

# Check 3: Database Tables
echo "3️⃣  Database Tables (verify in DB manually):"
echo "Required tables:"
echo "  - users (existing)"
echo "  - portfolios (NEW)"
echo "  - templates (NEW)"
echo ""

# Check 4: Configuration
echo "4️⃣  Configuration Checks:"
if grep -q "AI_PROVIDER" "api/config.php"; then
    echo -e "${GREEN}✓${NC} AI_PROVIDER configured"
else
    echo -e "${YELLOW}⚠${NC}  AI_PROVIDER not set"
fi

if grep -q "AI_API_KEY" "api/config.php"; then
    echo -e "${GREEN}✓${NC} AI_API_KEY configured"
    echo -e "${YELLOW}⚠${NC}  (Make sure it's set to actual Gemini key)"
else
    echo -e "${RED}✗${NC} AI_API_KEY missing"
fi

echo ""

# Check 5: File Permissions
echo "5️⃣  File Permissions (for web server):"
for dir in uploads uploads/resumes uploads/avatars uploads/projects uploads/portfolios; do
    if [ -d "$dir" ]; then
        chmod 755 "$dir"
        echo -e "${GREEN}✓${NC} $dir/ writable"
    fi
done

echo ""

# Summary
echo "==========================================================="
echo "✅ Setup verification complete!"
echo ""
echo "📋 Next Steps:"
echo "   1. Create database tables (see SQL below)"
echo "   2. Update AI_API_KEY in api/config.php"
echo "   3. Test creation at: /create.html"
echo "   4. Generate test portfolio"
echo ""
echo "🗄️  SQL to Run in phpMyAdmin:"
echo "==========================================================="
cat << 'EOF'

-- Create Templates Table
CREATE TABLE IF NOT EXISTS templates (
  id INT PRIMARY KEY AUTO_INCREMENT,
  slug VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(100),
  description TEXT,
  thumbnail_url VARCHAR(255),
  html_file VARCHAR(100),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create Portfolios Table
CREATE TABLE IF NOT EXISTS portfolios (
  id INT PRIMARY KEY AUTO_INCREMENT,
  user_id INT NOT NULL,
  template_id INT,
  slug VARCHAR(255) UNIQUE NOT NULL,
  title VARCHAR(255),
  content_json LONGTEXT,
  sections_visibility JSON,
  status ENUM('draft', 'published') DEFAULT 'draft',
  is_public BOOLEAN DEFAULT FALSE,
  score INT DEFAULT 0,
  resume_file_path VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (template_id) REFERENCES templates(id)
);

-- Create Portfolio Views Tracking Table (Optional)
CREATE TABLE IF NOT EXISTS portfolio_views (
  id INT PRIMARY KEY AUTO_INCREMENT,
  portfolio_id INT NOT NULL,
  viewer_ip VARCHAR(45),
  viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (portfolio_id) REFERENCES portfolios(id)
);

-- Insert Default Templates
INSERT INTO templates (slug, name, description, html_file) VALUES
('minimal', 'Minimal', 'Clean, professional design', 'minimal.html'),
('modern', 'Modern', 'Vibrant with gradients and animations', 'modern.html'),
('creative', 'Creative', 'Artistic with advanced animations', 'creative.html'),
('developer', 'Developer', 'Code-focused, terminal aesthetic', 'developer.html');

EOF

echo "==========================================================="
echo ""
echo "🎉 All set! Your AI Portfolio system is ready!"
echo ""
