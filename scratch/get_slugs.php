<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$res = $conn->query("SELECT id, slug FROM portfolios WHERE id IN (4,5,6,7)");
while ($row = $res->fetch_assoc()) {
    echo "Portfolio " . $row['id'] . " slug: " . $row['slug'] . "\n";
}

$conn->close();
?>
