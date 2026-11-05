<?php
require 'api/config.php';
$res = $conn->query('SELECT id, name FROM templates WHERE id BETWEEN 41 AND 70');
while($row = $res->fetch_assoc()) {
    echo $row['id'] . ": " . $row['name'] . "\n";
}
?>
