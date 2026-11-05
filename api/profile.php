<?php
/**
 * CreativePort — Profile Management API
 * Handles: get profile, update profile, upload avatar
 */
require_once __DIR__ . '/config.php';

$action = $_GET['action'] ?? (getRequestBody()['action'] ?? '');

switch ($action) {

    // ─── GET PROFILE ───────────────────────────────────────
    case 'get':
        $authUser = requireAuth();
        
        $stmt = $conn->prepare("
            SELECT id, name, email, avatar, role, phone, phone_country, birthday,
                   location, bio, education, company, website, job_title, experience,
                   skills_json, social_links_json, target_role, created_at
            FROM users WHERE id = ?
        ");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        if (!$user) {
            sendError('User not found.', 404);
        }

        // Decode JSON fields
        $user['skills'] = $user['skills_json'] ? json_decode($user['skills_json'], true) : [];
        $user['social_links'] = $user['social_links_json'] ? json_decode($user['social_links_json'], true) : [];
        unset($user['skills_json'], $user['social_links_json']);

        // Get portfolio count
        $stmt = $conn->prepare("SELECT COUNT(*) as count FROM portfolios WHERE user_id = ?");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $countResult = $stmt->get_result()->fetch_assoc();
        $user['portfolio_count'] = $countResult['count'];
        $stmt->close();

        // Get total views
        $stmt = $conn->prepare("
            SELECT COUNT(*) as total_views FROM portfolio_views pv
            JOIN portfolios p ON pv.portfolio_id = p.id
            WHERE p.user_id = ?
        ");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $viewResult = $stmt->get_result()->fetch_assoc();
        $user['total_views'] = $viewResult['total_views'];
        $stmt->close();

        // Calculate profile completeness
        $completeness = 0;
        $fields = ['name', 'email', 'avatar', 'phone', 'birthday', 'location', 'bio', 'education', 'company', 'website', 'job_title'];
        $total = count($fields);
        foreach ($fields as $field) {
            if (!empty($user[$field])) $completeness++;
        }
        if (!empty($user['skills']) && count($user['skills']) > 0) $completeness++;
        $total++;
        if (!empty($user['social_links'])) $completeness++;
        $total++;
        $user['profile_completeness'] = round(($completeness / $total) * 100);

        sendSuccess(['user' => $user]);
        break;

    // ─── UPDATE PROFILE ────────────────────────────────────
    case 'update':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();
        $data = getRequestBody();

        // Allowed fields
        $allowedFields = [
            'name', 'phone', 'phone_country', 'birthday', 'location', 'bio',
            'education', 'company', 'website', 'job_title', 'experience', 'target_role'
        ];

        $updates = [];
        $types = '';
        $values = [];

        foreach ($allowedFields as $field) {
            if (isset($data[$field])) {
                $updates[] = "$field = ?";
                $types .= 's';
                $values[] = sanitize($data[$field]);
            }
        }

        // Handle skills (array → JSON)
        if (isset($data['skills'])) {
            $skills = is_array($data['skills']) ? $data['skills'] : explode(',', $data['skills']);
            $skills = array_map('sanitize', $skills);
            $skills = array_filter($skills);
            $updates[] = "skills_json = ?";
            $types .= 's';
            $values[] = json_encode(array_values($skills));
        }

        // Handle social links (object → JSON)
        if (isset($data['social_links'])) {
            $updates[] = "social_links_json = ?";
            $types .= 's';
            $values[] = json_encode(sanitizeArray($data['social_links']));
        }

        if (empty($updates)) {
            sendError('No fields to update.');
        }

        // Add user ID for WHERE clause
        $types .= 'i';
        $values[] = $authUser['id'];

        $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$values);

        if ($stmt->execute()) {
            // Update session name if changed
            if (isset($data['name'])) {
                $_SESSION['user_name'] = trim($data['name']);
            }
            $stmt->close();
            sendSuccess([], 'Profile updated successfully.');
        } else {
            $stmt->close();
            sendError('Failed to update profile.', 500);
        }
        break;

    // ─── UPLOAD AVATAR ─────────────────────────────────────
    case 'upload_avatar':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $result = handleFileUpload('avatar', AVATAR_DIR, MAX_AVATAR_SIZE, [
            'image/jpeg', 'image/png', 'image/gif', 'image/webp'
        ]);

        if (isset($result['error'])) {
            sendError($result['error']);
        }

        // Delete old avatar if exists
        $stmt = $conn->prepare("SELECT avatar FROM users WHERE id = ?");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $oldAvatar = $stmt->get_result()->fetch_assoc()['avatar'];
        $stmt->close();

        if ($oldAvatar && file_exists(__DIR__ . '/../' . $oldAvatar)) {
            unlink(__DIR__ . '/../' . $oldAvatar);
        }

        // Save new avatar path
        $stmt = $conn->prepare("UPDATE users SET avatar = ? WHERE id = ?");
        $stmt->bind_param("si", $result['path'], $authUser['id']);
        $stmt->execute();
        $stmt->close();

        sendSuccess(['avatar_url' => $result['path']], 'Avatar uploaded successfully.');
        break;

    // ─── DELETE AVATAR ─────────────────────────────────────
    case 'delete_avatar':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        // Get current avatar path
        $stmt = $conn->prepare("SELECT avatar FROM users WHERE id = ?");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$user) {
            sendError('User not found.', 404);
        }

        if ($user['avatar']) {
            $avatarPath = __DIR__ . '/../' . $user['avatar'];
            if (file_exists($avatarPath)) {
                unlink($avatarPath);
            }

            // Remove from database
            $stmt = $conn->prepare("UPDATE users SET avatar = NULL WHERE id = ?");
            $stmt->bind_param("i", $authUser['id']);
            if ($stmt->execute()) {
                $stmt->close();
                sendSuccess([], 'Avatar deleted successfully.');
            } else {
                $stmt->close();
                sendError('Failed to delete avatar from database.', 500);
            }
        } else {
            sendError('No avatar to delete.');
        }
        break;

    default:
        sendError('Invalid action. Valid actions: get, update, upload_avatar, delete_avatar', 400);
        break;
}

$conn->close();
?>
