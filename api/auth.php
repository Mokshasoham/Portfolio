<?php
/**
 * CreativePort — Authentication API
 * Handles: login, signup, logout, session check, forgot/reset password
 */
require_once __DIR__ . '/config.php';

$data = getRequestBody();
$action = $data['action'] ?? ($_GET['action'] ?? '');

switch ($action) {

    // ─── LOGIN ─────────────────────────────────────────────
    case 'login':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);

        $email = filter_var(trim($data['email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $password = $data['password'] ?? '';

        if (!$email || empty($password)) {
            sendError('Email and password are required.');
        }

        $stmt = $conn->prepare("SELECT id, name, email, password, avatar, job_title, location FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            $stmt->close();
            sendError('No account found with that email.', 404);
        }

        $user = $result->fetch_assoc();
        $stmt->close();

        if (!password_verify($password, $user['password'])) {
            sendError('Incorrect password.', 401);
        }

        // Set session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_email'] = $user['email'];

        sendSuccess([
            'user' => [
                'id' => $user['id'],
                'name' => $user['name'],
                'email' => $user['email'],
                'avatar' => $user['avatar'],
                'job_title' => $user['job_title'],
                'location' => $user['location']
            ],
            'redirect' => 'dashboard.html'
        ], 'Login successful');
        break;

    // ─── SIGNUP ────────────────────────────────────────────
    case 'signup':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);

        $name = trim($data['name'] ?? '');
        $email = filter_var(trim($data['email'] ?? ''), FILTER_VALIDATE_EMAIL);
        $password = $data['password'] ?? '';
        $confirmPassword = $data['confirm_password'] ?? '';

        // Validation
        if (empty($name) || !$email || empty($password) || empty($confirmPassword)) {
            sendError('All fields are required.');
        }
        if (!$email) {
            sendError('Invalid email format.');
        }
        if (strlen($password) < 8) {
            sendError('Password must be at least 8 characters.');
        }
        if ($password !== $confirmPassword) {
            sendError('Passwords do not match.');
        }

        // Check if email exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows > 0) {
            $stmt->close();
            sendError('An account with this email already exists.', 409);
        }
        $stmt->close();

        // Create user
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
        $defaultSkills = json_encode(['HTML', 'CSS', 'JavaScript']);

        $stmt = $conn->prepare("INSERT INTO users (name, email, password, skills_json) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $name, $email, $hashedPassword, $defaultSkills);

        if ($stmt->execute()) {
            $userId = $stmt->insert_id;
            $stmt->close();

            // Set session
            $_SESSION['user_id'] = $userId;
            $_SESSION['user_name'] = $name;
            $_SESSION['user_email'] = $email;

            sendSuccess([
                'user' => [
                    'id' => $userId,
                    'name' => $name,
                    'email' => $email
                ],
                'redirect' => 'dashboard.html'
            ], 'Account created successfully');
        } else {
            $stmt->close();
            sendError('Registration failed. Please try again.', 500);
        }
        break;

    // ─── LOGOUT ────────────────────────────────────────────
    case 'logout':
        session_unset();
        session_destroy();
        sendSuccess([], 'Logged out successfully');
        break;

    // ─── CHECK SESSION ─────────────────────────────────────
    case 'check':
        $user = getCurrentUser();
        if ($user) {
            // Fetch full user data
            $stmt = $conn->prepare("SELECT id, name, email, avatar, job_title, location, bio, skills_json, social_links_json FROM users WHERE id = ?");
            $stmt->bind_param("i", $user['id']);
            $stmt->execute();
            $result = $stmt->get_result();
            $userData = $result->fetch_assoc();
            $stmt->close();

            if ($userData) {
                $userData['skills'] = $userData['skills_json'] ? json_decode($userData['skills_json'], true) : [];
                $userData['social_links'] = $userData['social_links_json'] ? json_decode($userData['social_links_json'], true) : [];
                unset($userData['skills_json'], $userData['social_links_json']);

                sendSuccess([
                    'loggedIn' => true,
                    'user' => $userData
                ]);
            }
        }
        sendSuccess(['loggedIn' => false]);
        break;

    // ─── FORGOT PASSWORD ───────────────────────────────────
    case 'forgot_password':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);

        $email = filter_var(trim($data['email'] ?? ''), FILTER_VALIDATE_EMAIL);
        if (!$email) {
            sendError('A valid email address is required.');
        }

        // Check if user exists
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            $stmt->close();
            // Don't reveal whether email exists — return success regardless
            sendSuccess([], 'If an account exists with that email, a reset link has been generated.');
        }
        $stmt->close();

        // Generate token
        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

        // Invalidate old tokens for this email
        $stmt = $conn->prepare("UPDATE password_resets SET used = 1 WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->close();

        // Insert new token
        $stmt = $conn->prepare("INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $email, $token, $expiresAt);
        $stmt->execute();
        $stmt->close();

        // In production, this would send an email. For local dev, return the token.
        sendSuccess([
            'reset_token' => $token,
            'expires_at' => $expiresAt,
            'reset_url' => "index.html?action=reset&token=" . $token,
            'note' => 'In production, this link would be sent via email.'
        ], 'Password reset link generated.');
        break;

    // ─── RESET PASSWORD ────────────────────────────────────
    case 'reset_password':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);

        $token = $data['token'] ?? '';
        $newPassword = $data['new_password'] ?? '';
        $confirmPassword = $data['confirm_password'] ?? '';

        if (empty($token) || empty($newPassword) || empty($confirmPassword)) {
            sendError('Token, new password, and confirmation are required.');
        }
        if (strlen($newPassword) < 8) {
            sendError('Password must be at least 8 characters.');
        }
        if ($newPassword !== $confirmPassword) {
            sendError('Passwords do not match.');
        }

        // Verify token
        $stmt = $conn->prepare("SELECT email, expires_at FROM password_resets WHERE token = ? AND used = 0");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            $stmt->close();
            sendError('Invalid or expired reset token.', 400);
        }

        $resetData = $result->fetch_assoc();
        $stmt->close();

        // Check expiry
        if (strtotime($resetData['expires_at']) < time()) {
            sendError('Reset token has expired. Please request a new one.', 400);
        }

        // Update password
        $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
        $stmt->bind_param("ss", $hashedPassword, $resetData['email']);
        $stmt->execute();
        $stmt->close();

        // Mark token as used
        $stmt = $conn->prepare("UPDATE password_resets SET used = 1 WHERE token = ?");
        $stmt->bind_param("s", $token);
        $stmt->execute();
        $stmt->close();

        sendSuccess([], 'Password has been reset successfully. You can now log in.');
        break;

    // ─── UNKNOWN ACTION ────────────────────────────────────
    default:
        sendError('Invalid action. Valid actions: login, signup, logout, check, forgot_password, reset_password', 400);
        break;
}

$conn->close();
?>
