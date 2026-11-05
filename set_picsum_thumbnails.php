<?php
require_once 'api/config.php';
$conn->query("UPDATE templates SET preview_image = CONCAT('https://picsum.photos/seed/', slug, '/600/400')");
echo "Updated " . $conn->affected_rows . " thumbnails to Picsum.\n";
?>
