<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$res = $conn->query("SELECT id, name, avatar FROM users");
while ($row = $res->fetch_assoc()) {
    echo "User " . $row['id'] . ": " . $row['name'] . " - Avatar: " . $row['avatar'] . "\n";
}

$conn->close();
?>
