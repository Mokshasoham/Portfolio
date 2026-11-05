<?php
require_once 'api/config.php';
$res = $conn->query("SELECT slug, preview_image FROM templates");
while($row = $res->fetch_assoc()) {
    echo $row['slug'] . " | " . $row['preview_image'] . "\n";
}
?>
