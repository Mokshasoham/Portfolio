<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$conn->query("UPDATE templates SET preview_image = 'https://picsum.photos/seed/watercolor/600/400' WHERE id = 72");
echo "Updated: " . $conn->affected_rows . "\n";
?>
