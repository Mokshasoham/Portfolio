<?php
require 'api/config.php';

echo "=== CHECKING PORTFOLIOS TABLE ===\n";
$result = $conn->query("DESCRIBE portfolios");
echo "Columns in portfolios table:\n";
while($row = $result->fetch_assoc()) {
    echo "  - " . $row['Field'] . " (" . $row['Type'] . ")\n";
}

echo "\n=== CHECKING FOR PIXABAY IMAGE IN PORTFOLIOS ===\n";
$count = $conn->query("SELECT COUNT(*) as total FROM portfolios WHERE html_content LIKE '%pixabay%'")->fetch_assoc();
echo "Portfolios with pixabay image: " . $count['total'] . "\n";
?>
