<?php
$file = __DIR__ . '/portifolio/about.html';
$content = file_get_contents($file);

$old_pattern = <<<'HTML'
<img src="https://cdn.pixabay.com/animation/2022/10/18/14/08/14-08-32-841_512.gif" 
                                 alt="Team Member" 
                                 class="team-image w-full h-64 object-cover">
HTML;

$new_avatar = <<<'SVG'
<svg viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg" alt="Team Member" class="team-image w-full h-64 object-cover" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius: 8px;">
                                    <defs>
                                        <style>
                                            @keyframes team-float { 0%, 100% { transform: translateY(0px); } 50% { transform: translateY(-8px); } }
                                            .team-avatar { animation: team-float 3s ease-in-out infinite; }
                                        </style>
                                    </defs>
                                    <circle cx="50" cy="35" r="18" class="team-avatar" fill="#ffffff" opacity="0.9"/>
                                    <ellipse cx="50" cy="70" rx="22" ry="18" class="team-avatar" fill="#ffffff" opacity="0.7"/>
                                    <circle cx="38" cy="28" r="3" fill="#667eea" opacity="0.6"/>
                                    <circle cx="62" cy="30" r="3" fill="#764ba2" opacity="0.6"/>
                                </svg>
SVG;

$new_content = str_replace($old_pattern, $new_avatar, $content);

if(file_put_contents($file, $new_content)) {
    $count = substr_count($content, 'pixabay') - substr_count($new_content, 'pixabay');
    echo "✓ Updated portifolio/about.html\n";
    echo "  Replaced " . $count . " instances\n";
} else {
    echo "✗ Failed to update\n";
}
?>
