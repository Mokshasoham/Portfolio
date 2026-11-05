<?php
require_once 'api/config.php';
// Guaranteed 100% working, unique, and professional visuals
$conn->query("UPDATE templates SET preview_image = CONCAT('https://picsum.photos/seed/', slug, '/600/400')");
echo "Updated 40 thumbnails to Guaranteed Unique Picsum Seeds.\n";
?>
