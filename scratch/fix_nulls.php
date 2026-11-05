<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Conn failed");
$res = $conn->query("UPDATE templates SET preview_image = CONCAT('https://picsum.photos/seed/', slug, '/600/400') WHERE preview_image IS NULL");
if ($res) {
    echo "Success. Rows updated: " . $conn->affected_rows . "\n";
} else {
    echo "Error: " . $conn->error . "\n";
}
$conn->close();
?>
