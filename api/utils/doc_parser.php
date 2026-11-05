<?php
/**
 * DOC/DOCX Text Extraction - No external dependencies
 */

function extractTextFromDoc($filePath) {
    $ext = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
    
    if ($ext === 'docx') {
        return extractFromDocx($filePath);
    } else {
        return extractFromDoc($filePath);
    }
}

/**
 * Extract text from DOCX (ZIP-based XML)
 */
function extractFromDocx($filePath) {
    $text = '';

    // DOCX files are ZIP archives
    $zip = @zip_open($filePath);
    if (!$zip) {
        return '';
    }

    while ($entry = @zip_read($zip)) {
        $name = zip_entry_name($entry);
        
        // Extract from document.xml which contains the main content
        if ($name === 'word/document.xml') {
            $size = zip_entry_filesize($entry);
            if ($size > 0) {
                $xml = zip_entry_read($entry, $size);
                
                // Extract text from XML
                // Remove all XML tags and decode entities
                $text = preg_replace('/<[^>]+>/', ' ', $xml);
                $text = html_entity_decode($text);
                $text = preg_replace('/\s+/', ' ', $text);
            }
        }
    }

    zip_close($zip);
    return trim($text);
}

/**
 * Extract text from DOC (binary format)
 */
function extractFromDoc($filePath) {
    $content = file_get_contents($filePath);
    $text = '';

    // DOC files contain text in between OLE compound document markers
    // Try to find readable text sections
    
    // Method 1: Look for chunks of text
    if (preg_match_all('/[\x20-\x7E]{4,}/', $content, $matches)) {
        $text = implode(' ', $matches[0]);
    }

    // Method 2: Remove binary data
    if (strlen($text) < 100) {
        $text = preg_replace('/[^\x20-\x7E\n\r\t]/', '', $content);
    }

    // Clean up
    $text = preg_replace('/\s+/', ' ', $text);
    return trim($text);
}
?>
