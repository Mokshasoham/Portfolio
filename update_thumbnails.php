<?php
require_once 'api/config.php';
$conn->query("UPDATE templates SET preview_image = CONCAT('images/thumbnails/', slug, '.png')");
echo "Updated " . $conn->affected_rows . " template thumbnails.\n";
?>
