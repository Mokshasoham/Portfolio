<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$res = $conn->query("SELECT slug FROM portfolios ORDER BY id DESC LIMIT 1");
print_r($res->fetch_assoc());
?>
