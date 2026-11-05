# 🚀 Premium Features Guide

## Overview
Your AI-powered portfolio builder includes several premium features to enhance portfolio functionality and user experience.

---

## 1. 📊 Analytics & Performance Tracking

### Features
- **View Tracking**: Monitor how many people viewed your portfolio
- **Unique Visitors**: Track distinct visitor IP addresses
- **Traffic Sources**: See where visitors are coming from (referrers)
- **Location Analytics**: Understand visitor geographic distribution
- **Daily Statistics**: View daily view counts and visitor trends

### API Endpoints

#### Track a View
```php
GET /api/analytics.php?action=track_view&portfolio_id=1
```

#### Get Portfolio Analytics
```php
GET /api/analytics.php?action=get_analytics&portfolio_id=1

Response:
{
  "success": true,
  "data": {
    "total_views": 156,
    "unique_visitors": 89,
    "days_active": 12,
    "avg_views_per_day": 13.0,
    "first_view": "2026-04-20 10:30:00",
    "last_view": "2026-04-26 15:45:00"
  }
}
```

#### Get Traffic Sources
```php
GET /api/analytics.php?action=get_traffic_sources&portfolio_id=1&limit=10

Response:
{
  "success": true,
  "data": [
    {"referrer": "google.com", "count": 45},
    {"referrer": "twitter.com", "count": 23},
    ...
  ]
}
```

#### Get Visitor Locations
```php
GET /api/analytics.php?action=get_locations&portfolio_id=1&limit=10

Response:
{
  "success": true,
  "data": [
    {"country": "United States", "count": 67},
    {"country": "United Kingdom", "count": 15},
    ...
  ]
}
```

#### Get Daily Statistics
```php
GET /api/analytics.php?action=get_daily_stats&portfolio_id=1&days=30

Response:
{
  "success": true,
  "data": [
    {"date": "2026-04-26", "views": 12, "visitors": 8},
    {"date": "2026-04-25", "views": 9, "visitors": 6},
    ...
  ]
}
```

---

## 2. 📁 Version Control & History

### Features
- **Version Snapshots**: Save complete portfolio snapshots at any time
- **Version History**: View all previous versions with timestamps
- **One-Click Restore**: Restore any previous version instantly
- **Version Management**: Delete old versions to keep history clean
- **Automatic Backups**: System creates backups when restoring versions

### API Endpoints

#### Create a Version
```php
POST /api/version_control.php?portfolio_id=1&action=create_version

Body:
{
  "version_name": "Design v2.1"
}

Response:
{
  "success": true,
  "version_id": 42,
  "message": "Version created successfully"
}
```

#### Get All Versions
```php
GET /api/version_control.php?portfolio_id=1&action=get_versions

Response:
{
  "success": true,
  "versions": [
    {
      "id": 42,
      "version_name": "Design v2.1",
      "created_at": "2026-04-26 15:30:00"
    },
    {
      "id": 41,
      "version_name": "Design v2.0",
      "created_at": "2026-04-25 10:00:00"
    },
    ...
  ]
}
```

#### Restore a Version
```php
POST /api/version_control.php?portfolio_id=1&action=restore_version

Body:
{
  "version_id": 41
}

Response:
{
  "success": true,
  "message": "Portfolio restored successfully"
}
```

#### Delete a Version
```php
POST /api/version_control.php?portfolio_id=1&action=delete_version

Body:
{
  "version_id": 40
}

Response:
{
  "success": true,
  "message": "Version deleted"
}
```

---

## 3. 🔍 SEO Optimization

### Features
- **SEO Score**: Get a score (0-100) based on portfolio completeness
- **SEO Suggestions**: Actionable recommendations to improve visibility
- **Meta Tags**: Auto-generated Open Graph tags for social sharing
- **Twitter Cards**: Optimized preview cards for Twitter/X
- **Structured Data**: JSON-LD schema for search engines
- **Meta Descriptions**: Optimized descriptions for search results

### API Endpoints

#### Get SEO Score & Suggestions
```php
GET /api/seo_optimizer.php?portfolio_id=1&action=get_seo_score

Response:
{
  "success": true,
  "data": {
    "score": 72,
    "grade": "C",
    "suggestions": [
      {
        "issue": "Short or missing biography",
        "priority": "high"
      },
      {
        "issue": "Add at least 3 projects",
        "priority": "medium"
      }
    ]
  }
}
```

#### Get Open Graph Tags
```php
GET /api/seo_optimizer.php?portfolio_id=1&action=get_og_tags

Response:
{
  "success": true,
  "html": "<meta property=\"og:title\" content=\"John Doe\">\n<meta property=\"og:description\" content=\"Full Stack Developer...\">\n..."
}
```

#### Get Twitter Card Tags
```php
GET /api/seo_optimizer.php?portfolio_id=1&action=get_twitter_tags

Response:
{
  "success": true,
  "html": "<meta name=\"twitter:card\" content=\"summary_large_image\">\n..."
}
```

#### Get Structured Data (JSON-LD)
```php
GET /api/seo_optimizer.php?portfolio_id=1&action=get_structured_data

Response:
{
  "success": true,
  "html": "<script type=\"application/ld+json\">{...}</script>"
}
```

#### Get Meta Description
```php
GET /api/seo_optimizer.php?portfolio_id=1&action=get_meta_description

Response:
{
  "success": true,
  "description": "John Doe - Full Stack Developer with 8 years of experience..."
}
```

---

## 4. 📄 PDF Export

### Features
- **HTML to PDF**: Convert portfolios to downloadable PDF files
- **Custom Styling**: PDFs respect your portfolio's design
- **Print-Friendly**: Optimized for printing and saving
- **Batch Export**: Export multiple portfolios

### API Endpoints

#### Export Portfolio as PDF
```php
GET /api/pdf_export.php?action=export_pdf&portfolio_id=1

Response:
{
  "success": true,
  "filename": "portfolio_1_1682156400.pdf",
  "path": "uploads/projects/portfolio_1_1682156400.pdf",
  "message": "PDF generation prepared"
}
```

### Implementation Notes
- Current implementation generates HTML files ready for PDF conversion
- For production PDF generation, install [DOMPDF](https://github.com/dompdf/dompdf):
  ```bash
  composer require dompdf/dompdf
  ```
- Alternative: Use online PDF conversion services (Puppeteer, wkhtmltopdf)

---

## 5. 🎨 Advanced Customization

### Custom CSS & JavaScript
Each template supports custom CSS injection:

```javascript
// In create.html
const customCSS = `
  .hero { background: linear-gradient(45deg, #667eea, #764ba2); }
  .title { font-size: 3rem; }
`;
```

### Template Variables
All templates support dynamic variable replacement:

```html
<!-- In template -->
<h1>{{name}}</h1>
<p>{{job_title}}</p>
<div>{{bio}}</div>

<!-- Skills loop -->
<ul>
  {{#skills}}
    <li>{{.}}</li>
  {{/skills}}
</ul>

<!-- Conditional sections -->
{{#if email}}
  <a href="mailto:{{email}}">Email Me</a>
{{/if}}
```

---

## 6. 🔐 Best Practices

### Security
✅ All API endpoints use prepared statements (SQL injection protected)
✅ File uploads validated by type and size
✅ Session-based authentication
✅ CORS headers configured

### Performance
✅ Database indexes on frequently queried columns
✅ Lazy loading for large datasets
✅ Caching recommendations for analytics
✅ Efficient file handling

### Maintenance
✅ Automatic database backups before version restores
✅ Version history limited to last 50 versions (configurable)
✅ Regular cleanup of old analytics data (optional)
✅ Error logging for debugging

---

## 7. 🚀 Quick Start Examples

### JavaScript Usage
```javascript
// Track a portfolio view
async function trackView(portfolioId) {
  const response = await fetch(
    `/api/analytics.php?action=track_view&portfolio_id=${portfolioId}`,
    { method: 'GET' }
  );
  const data = await response.json();
  console.log('View tracked:', data);
}

// Get analytics
async function getAnalytics(portfolioId) {
  const response = await fetch(
    `/api/analytics.php?action=get_analytics&portfolio_id=${portfolioId}`
  );
  const data = await response.json();
  return data.data;
}

// Create version
async function saveVersion(portfolioId, versionName) {
  const response = await fetch(
    `/api/version_control.php?portfolio_id=${portfolioId}&action=create_version`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ version_name: versionName })
    }
  );
  return await response.json();
}

// Get SEO score
async function getSEOScore(portfolioId) {
  const response = await fetch(
    `/api/seo_optimizer.php?portfolio_id=${portfolioId}&action=get_seo_score`
  );
  const data = await response.json();
  return data.data;
}
```

---

## 8. 📈 Analytics Dashboard Example

```html
<div class="analytics-dashboard">
  <div class="stat-card">
    <h3>Total Views</h3>
    <p class="stat-value" id="total-views">0</p>
  </div>
  <div class="stat-card">
    <h3>Unique Visitors</h3>
    <p class="stat-value" id="unique-visitors">0</p>
  </div>
  <div class="stat-card">
    <h3>SEO Score</h3>
    <p class="stat-value" id="seo-score">0</p>
  </div>
</div>

<script>
async function loadAnalytics(portfolioId) {
  const analytics = await getAnalytics(portfolioId);
  document.getElementById('total-views').textContent = analytics.total_views;
  document.getElementById('unique-visitors').textContent = analytics.unique_visitors;
  
  const seo = await getSEOScore(portfolioId);
  document.getElementById('seo-score').textContent = seo.score + '/100';
}
</script>
```

---

## 9. 📞 Support & Troubleshooting

### Common Issues

**Analytics not tracking views?**
- Ensure `portfolio_views` table exists
- Check that portfolio ID is valid
- Verify CORS headers are set correctly

**Version restore failing?**
- Check that version exists for the portfolio
- Ensure `portfolio_versions` table is created
- Verify user has permission to modify portfolio

**SEO score showing 0?**
- Populate all portfolio fields (name, bio, email, etc.)
- Add at least 3 projects
- Include social media links

**PDF export not working?**
- Install DOMPDF library for true PDF generation
- Current implementation creates HTML file ready for conversion
- Use online conversion services for immediate PDF export

---

## 10. 🎯 Future Enhancements

Planned features for upcoming releases:
- [ ] Multi-language portfolio support
- [ ] Custom domain mapping
- [ ] Email notifications for new views
- [ ] A/B testing different templates
- [ ] Visitor heatmaps
- [ ] Advanced AI suggestions
- [ ] Integration with LinkedIn
- [ ] Portfolio collaboration features
- [ ] Visitor feedback form
- [ ] Portfolio cloning/templates marketplace

---

**Last Updated:** April 26, 2026
**Version:** 1.2.0 (Premium Features Enabled)
