<?php
require 'api/config.php';
$res = $conn->query('SELECT COUNT(*) as total FROM templates');
$total = $res->fetch_assoc()['total'];
echo "Total templates in DB: " . $total . "\n";

$res = $conn->query('SELECT name, slug FROM templates ORDER BY id DESC LIMIT 5');
echo "Latest 5 templates:\n";
while($row = $res->fetch_assoc()) {
    echo " - " . $row['name'] . " (" . $row['slug'] . ")\n";
}
?>
