<?php
require 'api/config.php';
$res = $conn->query('SELECT id, slug FROM templates WHERE id BETWEEN 71 AND 90');
while($row = $res->fetch_assoc()) {
    echo $row['id'] . ": " . $row['slug'] . "\n";
}
?>
