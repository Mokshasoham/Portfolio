<?php
/**
 * CreativePort — Feedback API (Consolidated)
 * Uses portfolio_db instead of separate feedback_system DB
 */
require_once __DIR__ . '/config.php';

$action = $_GET['action'] ?? (getRequestBody()['action'] ?? 'submit');

switch ($action) {
    case 'submit':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);

        // Accept both JSON body and form POST
        $data = getRequestBody();
        if (empty($data)) {
            $data = $_POST;
        }

        $name = trim($data['name'] ?? '');
        $email = trim($data['email'] ?? '');
        $rating = intval($data['rating'] ?? 0);
        $feedbackType = trim($data['feedback_type'] ?? ($data['feedback-type'] ?? ''));
        $message = trim($data['message'] ?? '');

        if (empty($name) || empty($email) || empty($message)) {
            sendError('Name, email, and message are required.');
        }

        $userId = null;
        $user = getCurrentUser();
        if ($user) $userId = $user['id'];

        $stmt = $conn->prepare("INSERT INTO feedback (user_id, name, email, rating, feedback_type, message) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ississ", $userId, $name, $email, $rating, $feedbackType, $message);

        if ($stmt->execute()) {
            $stmt->close();
            sendSuccess([], 'Thank you! Your feedback has been submitted successfully.');
        } else {
            $stmt->close();
            sendError('Failed to submit feedback. Please try again.', 500);
        }
        break;

    case 'list':
        // Admin only — list all feedback
        $authUser = requireAuth();

        $stmt = $conn->prepare("SELECT * FROM feedback ORDER BY created_at DESC LIMIT 100");
        $stmt->execute();
        $result = $stmt->get_result();
        $feedbacks = [];
        while ($row = $result->fetch_assoc()) {
            $feedbacks[] = $row;
        }
        $stmt->close();

        sendSuccess(['feedbacks' => $feedbacks]);
        break;

    default:
        sendError('Invalid action. Valid: submit, list', 400);
        break;
}

$conn->close();
?>
