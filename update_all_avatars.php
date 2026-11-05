<?php
$views_dir = __DIR__ . '/portfolio/views';
$files = glob($views_dir . '/*.php');

// Generic animated SVG avatar that works with all templates
$new_avatar = '<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" class="w-56 h-56 object-cover rounded-2xl border-4 border-current shadow-2xl">
                        <defs>
                            <linearGradient id="avatar-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                                <stop offset="0%" style="stop-color:currentColor;stop-opacity:0.8" />
                                <stop offset="100%" style="stop-color:currentColor;stop-opacity:0.4" />
                            </linearGradient>
                            <style>
                                @keyframes avatar-float { 0%, 100% { transform: translateY(0px) scale(1); } 50% { transform: translateY(-10px) scale(1.05); } }
                                @keyframes avatar-pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
                                .avatar-shape { animation: avatar-float 3s ease-in-out infinite; }
                                .avatar-accent { animation: avatar-pulse 2.5s ease-in-out infinite; }
                            </style>
                        </defs>
                        <!-- Main circle -->\n                        <circle cx="50" cy="35" r="20" class="avatar-shape" fill="url(#avatar-grad)"/>
                        <!-- Body -->\n                        <ellipse cx="50" cy="70" rx="25" ry="20" class="avatar-accent" fill="url(#avatar-grad)" opacity="0.6"/>
                        <!-- Accent circles -->\n                        <circle cx="35" cy="25" r="5" fill="currentColor" opacity="0.3"/>
                        <circle cx="65" cy="28" r="5" fill="currentColor" opacity="0.3"/>
                    </svg>';

$old_pattern = '<img src="https://cdn.pixabay.com/animation/2022/10/18/14/08/14-08-32-841_512.gif" class="w-56 h-56 object-cover rounded-2xl border-4 border-current shadow-2xl" alt="Avatar">';

$updated = 0;
$failed = 0;

echo "Updating all " . count($files) . " portfolio templates...\n\n";

foreach($files as $file) {
    $filename = basename($file);
    $content = file_get_contents($file);
    
    if(strpos($content, 'pixabay') !== false) {
        $new_content = str_replace($old_pattern, $new_avatar, $content);
        
        if(file_put_contents($file, $new_content)) {
            echo "[✓] " . $filename . " - Updated\n";
            $updated++;
        } else {
            echo "[✗] " . $filename . " - Failed to write\n";
            $failed++;
        }
    } else {
        echo "[-] " . $filename . " - No pixabay image found\n";
    }
}

echo "\n=== RESULTS ===\n";
echo "Total files checked: " . count($files) . "\n";
echo "Successfully updated: " . $updated . "\n";
echo "Failed: " . $failed . "\n";
?>
