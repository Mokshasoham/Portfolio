<?php
require 'c:/xampp1/htdocs/portifolio/api/config.php';
$res = $conn->query('SELECT COUNT(*) as total FROM templates');
if ($res) {
    echo "Total templates in xampp1 DB: " . $res->fetch_assoc()['total'] . "\n";
} else {
    echo "Error: " . $conn->error . "\n";
}
?>
