<?php
$servername = "localhost"; 
$username = "root";        
$password = "";            
$database = "feedback_system";


$conn = new mysqli($servername, $username, $password, $database);


if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}


$name = $conn->real_escape_string($_POST['name']);
$email = $conn->real_escape_string($_POST['email']);
$rating = intval($_POST['rating']);
$feedback_type = $conn->real_escape_string($_POST['feedback-type']);
$message = $conn->real_escape_string($_POST['message']);

$sql = "INSERT INTO feedback (name, email, rating, feedback_type, message)
        VALUES ('$name', '$email', '$rating', '$feedback_type', '$message')";

if ($conn->query($sql) === TRUE) {
    echo "Thank you! Your feedback has been submitted.";
} else {
    echo "Error: " . $sql . "<br>" . $conn->error;
}

$conn->close();
?>
