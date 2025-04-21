<?php
session_start();
header('Content-Type: application/json');


$conn = new mysqli("localhost", "root", "", "portfolio_db");
if ($conn->connect_error) {
    http_response_code(500);
    echo json_encode(["status" => "error", "message" => "Database connection failed"]);
    exit;
}


$json = file_get_contents('php://input');
$data = json_decode($json, true);


if ($_SERVER["REQUEST_METHOD"] === "POST") {
  
    $isSignup = isset($data['action']) && $data['action'] === 'signup';
    $isLogin = isset($data['action']) && $data['action'] === 'login';

    if ($isSignup) {
        
        $name = trim($data["name"]);
        $email = filter_var(trim($data["email"]), FILTER_VALIDATE_EMAIL);
        $password = $data["password"];
        $confirm_password = $data["confirm_password"] ?? '';

        
        if (empty($name) || empty($email) || empty($password) || empty($confirm_password)) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "All fields are required"]);
            exit;
        }

       
        if (!$email) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Invalid email format"]);
            exit;
        }

      
        if ($password !== $confirm_password) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Passwords do not match"]);
            exit;
        }

        
        if (strlen($password) < 8) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Password must be at least 8 characters"]);
            exit;
        }

        
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            http_response_code(409);
            echo json_encode(["status" => "error", "message" => "Email already registered"]);
            $stmt->close();
            $conn->close();
            exit;
        }
        $stmt->close();

       
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);

     
        $stmt = $conn->prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $name, $email, $hashed_password);

        if ($stmt->execute()) {
            $user_id = $stmt->insert_id;
            $_SESSION['user_id'] = $user_id;
            $_SESSION['user_name'] = $name;
            $_SESSION['user_email'] = $email;
            
            echo json_encode([
                "status" => "success",
                "message" => "Registration successful",
                "user" => [
                    "id" => $user_id,
                    "name" => $name,
                    "email" => $email
                ],
                "redirect" => "front.html"
            ]);
        } else {
            http_response_code(500);
            echo json_encode(["status" => "error", "message" => "Registration failed"]);
        }
        $stmt->close();
    }
    
    elseif ($isLogin) {
        $email = filter_var(trim($data["email"]), FILTER_VALIDATE_EMAIL);
        $password = $data["password"];

        
        if (empty($email) || empty($password)) {
            http_response_code(400);
            echo json_encode(["status" => "error", "message" => "Email and password are required"]);
            exit;
        }

        
        $stmt = $conn->prepare("SELECT id, name, email, password FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 1) {
            $user = $result->fetch_assoc();
            
            if (password_verify($password, $user['password'])) {
                
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['user_name'] = $user['name'];
                $_SESSION['user_email'] = $user['email'];
                
                echo json_encode([
                    "status" => "success",
                    "user" => [
                        "id" => $user['id'],
                        "name" => $user['name'],
                        "email" => $user['email']
                    ],
                    "redirect" => "front.html"
                ]);
            } else {
                http_response_code(401);
                echo json_encode(["status" => "error", "message" => "Incorrect password"]);
            }
        } else {
            http_response_code(404);
            echo json_encode(["status" => "error", "message" => "User not found"]);
        }
        $stmt->close();
    }
    else {
        http_response_code(400);
        echo json_encode(["status" => "error", "message" => "Invalid action"]);
    }
} else {
    http_response_code(405);
    echo json_encode(["status" => "error", "message" => "Method not allowed"]);
}

$conn->close();
?>