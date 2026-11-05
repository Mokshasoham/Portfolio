<?php
/**
 * PDF Export Feature
 * Converts portfolio HTML to PDF
 */

require_once 'config.php';

function generatePortfolioPDF($portfolio_id, $html_content = null) {
    global $conn;
    try {
        // Get portfolio if not provided
        if (!$html_content) {
            $stmt = $conn->prepare("SELECT content_json, title FROM portfolios WHERE id = ?");
            $stmt->bind_param("i", $portfolio_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 0) {
                return ['success' => false, 'error' => 'Portfolio not found'];
            }
            
            $portfolio = $result->fetch_assoc();
            $title = $portfolio['title'];
        } else {
            $title = "portfolio";
        }
        
        // Create PDF filename
        $pdf_filename = 'portfolio_' . $portfolio_id . '_' . time() . '.html';
        $pdf_path = PROJECT_DIR . $pdf_filename;
        
        // Use built-in HTML to PDF conversion (basic)
        // For production, use: https://github.com/dompdf/dompdf
        
        // Generate simple PDF using PHP
        $pdf_html = generatePDFHTML($html_content, $title);
        
        // Save as PDF (using file_put_contents for now - would use dompdf in production)
        // For demo, we'll save as HTML and provide conversion instructions
        
        file_put_contents($pdf_path, $pdf_html);
        
        return [
            'success' => true,
            'filename' => $pdf_filename,
            'path' => 'uploads/projects/' . $pdf_filename,
            'message' => 'Print-ready export generated. Use browser print or install DOMPDF for direct PDF files.',
            'file_type' => 'html'
        ];
    } catch (Exception $e) {
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

function generatePDFHTML($html, $title) {
    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$title - PDF Export</title>
    <style>
        * { margin: 0; padding: 0; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        @page { margin: 2cm; }
        @media print { body { margin: 0; } }
    </style>
</head>
<body>
    $html
</body>
</html>
HTML;
}

// API Endpoint
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['action']) && $_GET['action'] === 'export_pdf') {
    $portfolio_id = intval($_GET['portfolio_id'] ?? 0);
    
    if ($portfolio_id <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid portfolio ID']);
        exit;
    }
    
    $result = generatePortfolioPDF($portfolio_id);
    header('Content-Type: application/json');
    echo json_encode($result);
}
?>
