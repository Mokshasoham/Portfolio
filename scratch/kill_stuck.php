<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$res = $conn->query("SHOW FULL PROCESSLIST");
while($row = $res->fetch_assoc()) {
    if ($row['User'] == 'root' && $row['Info'] != 'SHOW FULL PROCESSLIST') {
        echo "Killing " . $row['Id'] . " (" . $row['Info'] . ")\n";
        $conn->query("KILL " . $row['Id']);
    }
}
?>
