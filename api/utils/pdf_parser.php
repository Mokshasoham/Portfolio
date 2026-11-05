<?php
/**
 * PDF Text Extraction - No external dependencies
 */

function extractTextFromPDF($filePath) {
    $content = file_get_contents($filePath);
    $text = '';

    // Extract text between BT and ET markers (PDF drawing operators)
    if (preg_match_all('/BT\s*(.*?)\s*ET/s', $content, $matches)) {
        foreach ($matches[1] as $block) {
            // Extract text in parentheses (literal strings)
            if (preg_match_all('/\((.*?)\)/', $block, $textMatches)) {
                $text .= implode(' ', $textMatches[1]) . "\n";
            }
            // Extract hex-encoded strings
            if (preg_match_all('/<([0-9A-Fa-f]+)>/', $block, $hexMatches)) {
                foreach ($hexMatches[1] as $hex) {
                    if (strlen($hex) % 2 === 0) {
                        $decoded = @hex2bin($hex);
                        if ($decoded) {
                            $text .= $decoded . ' ';
                        }
                    }
                }
            }
        }
    }

    // Try stream-based extraction if first method fails
    if (strlen(trim($text)) < 100) {
        if (preg_match_all('/stream\s*(.*?)\s*endstream/s', $content, $streams)) {
            foreach ($streams[1] as $stream) {
                $decoded = @gzuncompress($stream);
                if ($decoded) {
                    if (preg_match_all('/\((.*?)\)/', $decoded, $textMatches)) {
                        $text .= implode(' ', $textMatches[1]) . "\n";
                    }
                }
            }
        }
    }

    // Clean up extracted text
    $text = preg_replace('/[^\x20-\x7E\n\r\t]/u', '', $text);
    $text = preg_replace('/\n{3,}/', "\n\n", $text);
    $text = html_entity_decode($text);

    return trim($text);
}
?>
