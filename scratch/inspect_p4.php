<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$res = $conn->query("SELECT content_json FROM portfolios WHERE id = 4");
$row = $res->fetch_assoc();
echo $row['content_json'];

$conn->close();
?>
