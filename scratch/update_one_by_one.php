<?php
$conn = new mysqli('localhost', 'root', '', 'portfolio_db');
$res = $conn->query("SELECT id, slug FROM templates WHERE preview_image IS NULL");
echo "Found " . $res->num_rows . " templates with null images.\n";
while($row = $res->fetch_assoc()) {
    $id = $row['id'];
    $slug = $row['slug'];
    $img = "https://picsum.photos/seed/$slug/600/400";
    echo "Updating ID $id ($slug)... ";
    $conn->query("UPDATE templates SET preview_image = '$img' WHERE id = $id");
    echo "Done.\n";
}
$conn->close();
?>
