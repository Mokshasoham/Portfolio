<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Conn failed");

echo "Creating templates_new...\n";
$conn->query("CREATE TABLE templates_new LIKE templates");

echo "Copying data...\n";
$conn->query("INSERT INTO templates_new SELECT * FROM templates");

echo "Updating images in templates_new...\n";
$conn->query("UPDATE templates_new SET preview_image = CONCAT('https://picsum.photos/seed/', slug, '/600/400') WHERE preview_image IS NULL");

echo "Renaming tables...\n";
$conn->query("RENAME TABLE templates TO templates_old, templates_new TO templates");

echo "Done.\n";
$conn->close();
?>
