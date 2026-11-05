<?php
require 'api/config.php';
$res = $conn->query('SELECT COUNT(*) as total FROM templates WHERE preview_image IS NULL');
echo "Templates with NULL preview_image: " . $res->fetch_assoc()['total'] . "\n";
?>
