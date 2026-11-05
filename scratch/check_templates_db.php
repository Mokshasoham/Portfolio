<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$res = $conn->query("SELECT id, name, preview_image FROM templates");
while ($row = $res->fetch_assoc()) {
    echo "Template " . $row['id'] . " (" . $row['name'] . ") preview: " . $row['preview_image'] . "\n";
}

$conn->close();
?>
