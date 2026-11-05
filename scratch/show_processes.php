<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$res = $conn->query("SHOW FULL PROCESSLIST");
while($row = $res->fetch_assoc()) {
    print_r($row);
}
?>
