<?php
session_start();
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$res = $conn->query("SELECT * FROM users LIMIT 1");
$user = $res->fetch_assoc();
$_SESSION['user_id'] = $user['id'];
$_SESSION['user_name'] = $user['name'];
$_SESSION['user_email'] = $user['email'];
echo "Logged in as " . $user['name'];
header("Location: create.html");
?>
