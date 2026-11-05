<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$res = $conn->query("SELECT id, content_json FROM portfolios");
while ($row = $res->fetch_assoc()) {
    if (strpos($row['content_json'], 'moksha') !== false || strpos($row['content_json'], 'shivam') !== false || strpos($row['content_json'], 'jayanth') !== false) {
        echo "Portfolio " . $row['id'] . " contains personal image references!\n";
    }
}

$res = $conn->query("SELECT id, avatar FROM users");
while ($row = $res->fetch_assoc()) {
    echo "User " . $row['id'] . " avatar: " . $row['avatar'] . "\n";
}

$conn->close();
?>
