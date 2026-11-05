<?php
/**
 * CreativePort — Portfolio CRUD API
 * Handles: create, update, delete, get, list, publish, unpublish, switch_template
 */
require_once __DIR__ . '/config.php';

$data = getRequestBody();
$action = $data['action'] ?? ($_GET['action'] ?? '');

switch ($action) {

    // ─── CREATE PORTFOLIO ──────────────────────────────────
    case 'create':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $title = sanitize($data['title'] ?? 'My Portfolio');
        $templateId = intval($data['template_id'] ?? 1);
        $contentJson = sanitizeArray($data['content'] ?? []);
        $roleType = sanitize($data['role_type'] ?? '');

        $slug = generateUniqueSlug($conn, $title, $authUser['id']);
        $contentStr = is_string($contentJson) ? $contentJson : json_encode($contentJson);

        // Fetch user data for scoring
        $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $userData = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $scoreResult = calculatePortfolioScore($contentStr, $userData);

        // Sections visibility
        $sectionsVisibility = isset($data['sections_visibility']) ? json_encode($data['sections_visibility']) : json_encode([
            'about' => true,
            'skills' => true,
            'projects' => true,
            'experience' => true,
            'education' => true,
            'certifications' => true,
            'contact' => true
        ]);

        $stmt = $conn->prepare("
            INSERT INTO portfolios (user_id, template_id, title, slug, content_json, score, status, role_type, sections_visibility)
            VALUES (?, ?, ?, ?, ?, ?, 'draft', ?, ?)
        ");
        $stmt->bind_param("iisssiss", 
            $authUser['id'], $templateId, $title, $slug, 
            $contentStr, $scoreResult['score'], $roleType, $sectionsVisibility
        );

        if ($stmt->execute()) {
            $portfolioId = $stmt->insert_id;
            $stmt->close();
            sendSuccess([
                'id' => $portfolioId,
                'slug' => $slug,
                'score' => $scoreResult['score'],
                'suggestions' => $scoreResult['suggestions']
            ], 'Portfolio created successfully.');
        } else {
            $stmt->close();
            sendError('Failed to create portfolio.', 500);
        }
        break;

    // ─── UPDATE PORTFOLIO ──────────────────────────────────
    case 'update':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $portfolioId = intval($data['id'] ?? 0);
        if (!$portfolioId) sendError('Portfolio ID is required.');

        // Verify ownership
        $stmt = $conn->prepare("SELECT id FROM portfolios WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $portfolioId, $authUser['id']);
        $stmt->execute();
        $stmt->store_result();
        if ($stmt->num_rows === 0) {
            $stmt->close();
            sendError('Portfolio not found or access denied.', 404);
        }
        $stmt->close();

        $updates = [];
        $types = '';
        $values = [];

        if (isset($data['title'])) {
            $updates[] = "title = ?";
            $types .= 's';
            $values[] = sanitize($data['title']);
        }

        if (isset($data['content'])) {
            $contentStr = json_encode(sanitizeArray($data['content']));
            $updates[] = "content_json = ?";
            $types .= 's';
            $values[] = $contentStr;

            // Recalculate score
            $stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->bind_param("i", $authUser['id']);
            $stmt->execute();
            $userData = $stmt->get_result()->fetch_assoc();
            $stmt->close();

            $scoreResult = calculatePortfolioScore($contentStr, $userData);
            $updates[] = "score = ?";
            $types .= 'i';
            $values[] = $scoreResult['score'];
        }

        if (isset($data['template_id'])) {
            $updates[] = "template_id = ?";
            $types .= 'i';
            $values[] = intval($data['template_id']);
        }

        if (isset($data['role_type'])) {
            $updates[] = "role_type = ?";
            $types .= 's';
            $values[] = sanitize($data['role_type']);
        }

        if (isset($data['sections_visibility'])) {
            $updates[] = "sections_visibility = ?";
            $types .= 's';
            $values[] = json_encode($data['sections_visibility']);
        }

        if (empty($updates)) sendError('No fields to update.');

        $types .= 'i';
        $values[] = $portfolioId;

        $sql = "UPDATE portfolios SET " . implode(', ', $updates) . " WHERE id = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$values);

        if ($stmt->execute()) {
            $stmt->close();
            $response = ['message' => 'Portfolio updated successfully.'];
            if (isset($scoreResult)) {
                $response['score'] = $scoreResult['score'];
                $response['suggestions'] = $scoreResult['suggestions'];
            }
            sendSuccess($response);
        } else {
            $stmt->close();
            sendError('Failed to update portfolio.', 500);
        }
        break;

    // ─── DELETE PORTFOLIO ──────────────────────────────────
    case 'delete':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $portfolioId = intval($data['id'] ?? ($_GET['id'] ?? 0));
        if (!$portfolioId) sendError('Portfolio ID is required.');

        $stmt = $conn->prepare("DELETE FROM portfolios WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $portfolioId, $authUser['id']);
        $stmt->execute();

        if ($stmt->affected_rows > 0) {
            $stmt->close();
            sendSuccess([], 'Portfolio deleted successfully.');
        } else {
            $stmt->close();
            sendError('Portfolio not found or access denied.', 404);
        }
        break;

    // ─── GET SINGLE PORTFOLIO ──────────────────────────────
    case 'get':
        $portfolioId = intval($_GET['id'] ?? 0);
        $slug = $_GET['slug'] ?? '';

        if ($portfolioId) {
            $stmt = $conn->prepare("
                SELECT p.*, t.name as template_name, t.slug as template_slug, u.name as author_name, u.avatar as author_avatar
                FROM portfolios p
                LEFT JOIN templates t ON p.template_id = t.id
                JOIN users u ON p.user_id = u.id
                WHERE p.id = ?
            ");
            $stmt->bind_param("i", $portfolioId);
        } elseif ($slug) {
            $stmt = $conn->prepare("
                SELECT p.*, t.name as template_name, t.slug as template_slug, u.name as author_name, u.avatar as author_avatar
                FROM portfolios p
                LEFT JOIN templates t ON p.template_id = t.id
                JOIN users u ON p.user_id = u.id
                WHERE p.slug = ?
            ");
            $stmt->bind_param("s", $slug);
        } else {
            sendError('Portfolio ID or slug is required.');
        }

        $stmt->execute();
        $result = $stmt->get_result();
        $portfolio = $result->fetch_assoc();
        $stmt->close();

        if (!$portfolio) {
            sendError('Portfolio not found.', 404);
        }

        // Check access: if not published, only owner can view
        $currentUser = getCurrentUser();
        if ($portfolio['status'] !== 'published') {
            if (!$currentUser || $currentUser['id'] != $portfolio['user_id']) {
                sendError('This portfolio is not published.', 403);
            }
        }

        // Decode JSON fields
        $portfolio['content'] = $portfolio['content_json'] ? json_decode($portfolio['content_json'], true) : [];
        $portfolio['sections_visibility'] = $portfolio['sections_visibility'] ? json_decode($portfolio['sections_visibility'], true) : [];
        unset($portfolio['content_json']);

        sendSuccess(['portfolio' => $portfolio]);
        break;

    // ─── LIST USER'S PORTFOLIOS ────────────────────────────
    case 'list':
        $authUser = requireAuth();

        $stmt = $conn->prepare("
            SELECT p.id, p.title, p.slug, p.score, p.status, p.is_public, p.role_type,
                   p.created_at, p.updated_at,
                   t.name as template_name, t.slug as template_slug, t.preview_image,
                   (SELECT COUNT(*) FROM portfolio_views pv WHERE pv.portfolio_id = p.id) as view_count
            FROM portfolios p
            LEFT JOIN templates t ON p.template_id = t.id
            WHERE p.user_id = ?
            ORDER BY p.updated_at DESC
        ");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $result = $stmt->get_result();

        $portfolios = [];
        while ($row = $result->fetch_assoc()) {
            $portfolios[] = $row;
        }
        $stmt->close();

        sendSuccess(['portfolios' => $portfolios]);
        break;

    // ─── PUBLISH PORTFOLIO ─────────────────────────────────
    case 'publish':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $portfolioId = intval($data['id'] ?? 0);
        if (!$portfolioId) sendError('Portfolio ID is required.');

        // Verify existence and ownership
        $stmt = $conn->prepare("SELECT slug, status FROM portfolios WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $portfolioId, $authUser['id']);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            $stmt->close();
            sendError('Portfolio not found or access denied.', 404);
        }
        
        $row = $result->fetch_assoc();
        $slug = $row['slug'];
        $stmt->close();

        // Update status
        $stmt = $conn->prepare("UPDATE portfolios SET status = 'published' WHERE id = ?");
        $stmt->bind_param("i", $portfolioId);
        $stmt->execute();
        $stmt->close();

        sendSuccess([
            'live_url' => "portfolio/index.php?slug=" . urlencode($slug)
        ], 'Portfolio published! It is now live.');
        break;

    // ─── UNPUBLISH PORTFOLIO ───────────────────────────────
    case 'unpublish':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $portfolioId = intval($data['id'] ?? 0);
        if (!$portfolioId) sendError('Portfolio ID is required.');

        // Verify existence and ownership
        $stmt = $conn->prepare("SELECT id FROM portfolios WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $portfolioId, $authUser['id']);
        $stmt->execute();
        $stmt->store_result();
        
        if ($stmt->num_rows === 0) {
            $stmt->close();
            sendError('Portfolio not found or access denied.', 404);
        }
        $stmt->close();

        // Update status
        $stmt = $conn->prepare("UPDATE portfolios SET status = 'draft' WHERE id = ?");
        $stmt->bind_param("i", $portfolioId);
        $stmt->execute();
        $stmt->close();

        sendSuccess([], 'Portfolio unpublished. It is now a draft.');
        break;

    // ─── SWITCH TEMPLATE ───────────────────────────────────
    case 'switch_template':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $authUser = requireAuth();

        $portfolioId = intval($data['id'] ?? 0);
        $templateId = intval($data['template_id'] ?? 0);

        if (!$portfolioId || !$templateId) {
            sendError('Portfolio ID and template ID are required.');
        }

        $stmt = $conn->prepare("UPDATE portfolios SET template_id = ? WHERE id = ? AND user_id = ?");
        $stmt->bind_param("iii", $templateId, $portfolioId, $authUser['id']);
        $stmt->execute();

        if ($stmt->affected_rows > 0) {
            $stmt->close();
            sendSuccess([], 'Template switched successfully. Your content has been preserved.');
        } else {
            $stmt->close();
            sendError('Portfolio not found or access denied.', 404);
        }
        break;

    // ─── GET TEMPLATES LIST ────────────────────────────────
    case 'templates':
        $stmt = $conn->prepare("SELECT id, name, slug, description, preview_image, category, is_premium FROM templates ORDER BY id");
        $stmt->execute();
        $result = $stmt->get_result();

        $templates = [];
        while ($row = $result->fetch_assoc()) {
            $templates[] = $row;
        }
        $stmt->close();

        sendSuccess(['templates' => $templates]);
        break;

    default:
        sendError('Invalid action. Valid: create, update, delete, get, list, publish, unpublish, switch_template, templates', 400);
        break;
}

$conn->close();
?>
