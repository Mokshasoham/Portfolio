<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$res = $conn->query("SHOW TRIGGERS");
while($row = $res->fetch_assoc()) {
    print_r($row);
}
?>
