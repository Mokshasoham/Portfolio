<?php
require_once 'api/config.php';
$res = $conn->query("SELECT COUNT(*) as total FROM templates");
$row = $res->fetch_assoc();
echo "TOTAL_TEMPLATES: " . $row['total'] . "\n";

$res = $conn->query("SELECT slug FROM templates");
while($row = $res->fetch_assoc()) {
    echo "SLUG: " . $row['slug'] . "\n";
}
?>
