<?php
/**
 * CreativePort — Explore / Community API
 * Browse public portfolios, search, trending
 */
require_once __DIR__ . '/config.php';

$action = $_GET['action'] ?? '';

switch ($action) {

    // ─── BROWSE PORTFOLIOS ─────────────────────────────────
    case 'browse':
        $page = max(1, intval($_GET['page'] ?? 1));
        $limit = min(50, max(6, intval($_GET['limit'] ?? 12)));
        $offset = ($page - 1) * $limit;
        $skill = trim($_GET['skill'] ?? '');
        $role = trim($_GET['role'] ?? '');
        $sort = $_GET['sort'] ?? 'recent'; // recent, popular, score

        $where = "p.status = 'published' AND p.is_public = 1";
        $params = [];
        $types = '';

        if ($skill) {
            $where .= " AND JSON_SEARCH(p.content_json, 'all', ?, NULL, '$.skills') IS NOT NULL";
            $types .= 's';
            $params[] = $skill;
        }

        if ($role) {
            $where .= " AND p.role_type = ?";
            $types .= 's';
            $params[] = $role;
        }

        switch ($sort) {
            case 'popular':
                $orderBy = 'view_count DESC';
                break;
            case 'score':
                $orderBy = 'p.score DESC';
                break;
            default:
                $orderBy = 'p.updated_at DESC';
                break;
        }

        // Count total
        $countSql = "SELECT COUNT(*) as total FROM portfolios p WHERE $where";
        if ($types) {
            $stmt = $conn->prepare($countSql);
            $stmt->bind_param($types, ...$params);
        } else {
            $stmt = $conn->prepare($countSql);
        }
        $stmt->execute();
        $total = $stmt->get_result()->fetch_assoc()['total'];
        $stmt->close();

        // Fetch portfolios
        $sql = "
            SELECT p.id, p.title, p.slug, p.score, p.role_type, p.updated_at,
                   t.name as template_name, t.preview_image,
                   u.name as author_name, u.avatar as author_avatar, u.job_title as author_title,
                   (SELECT COUNT(*) FROM portfolio_views pv WHERE pv.portfolio_id = p.id) as view_count
            FROM portfolios p
            LEFT JOIN templates t ON p.template_id = t.id
            JOIN users u ON p.user_id = u.id
            WHERE $where
            ORDER BY $orderBy
            LIMIT ? OFFSET ?
        ";

        $allTypes = $types . 'ii';
        $allParams = array_merge($params, [$limit, $offset]);

        $stmt = $conn->prepare($sql);
        $stmt->bind_param($allTypes, ...$allParams);
        $stmt->execute();
        $result = $stmt->get_result();

        $portfolios = [];
        while ($row = $result->fetch_assoc()) {
            $portfolios[] = $row;
        }
        $stmt->close();

        sendSuccess([
            'portfolios' => $portfolios,
            'total' => $total,
            'page' => $page,
            'pages' => ceil($total / $limit)
        ]);
        break;

    // ─── TRENDING ──────────────────────────────────────────
    case 'trending':
        $limit = min(20, max(6, intval($_GET['limit'] ?? 6)));

        $stmt = $conn->prepare("
            SELECT p.id, p.title, p.slug, p.score, p.role_type,
                   t.name as template_name, t.preview_image,
                   u.name as author_name, u.avatar as author_avatar,
                   COUNT(pv.id) as view_count
            FROM portfolios p
            LEFT JOIN templates t ON p.template_id = t.id
            JOIN users u ON p.user_id = u.id
            LEFT JOIN portfolio_views pv ON pv.portfolio_id = p.id AND pv.viewed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            WHERE p.status = 'published' AND p.is_public = 1
            GROUP BY p.id
            ORDER BY view_count DESC, p.score DESC
            LIMIT ?
        ");
        $stmt->bind_param("i", $limit);
        $stmt->execute();
        $result = $stmt->get_result();

        $trending = [];
        while ($row = $result->fetch_assoc()) {
            $trending[] = $row;
        }
        $stmt->close();

        sendSuccess(['trending' => $trending]);
        break;

    // ─── SEARCH ────────────────────────────────────────────
    case 'search':
        $query = trim($_GET['q'] ?? '');
        if (empty($query)) sendError('Search query is required.');

        $searchTerm = '%' . $query . '%';
        $stmt = $conn->prepare("
            SELECT p.id, p.title, p.slug, p.score, p.role_type,
                   t.name as template_name, t.preview_image,
                   u.name as author_name, u.avatar as author_avatar,
                   (SELECT COUNT(*) FROM portfolio_views pv WHERE pv.portfolio_id = p.id) as view_count
            FROM portfolios p
            LEFT JOIN templates t ON p.template_id = t.id
            JOIN users u ON p.user_id = u.id
            WHERE p.status = 'published' AND p.is_public = 1
              AND (p.title LIKE ? OR u.name LIKE ? OR p.role_type LIKE ?)
            ORDER BY p.score DESC
            LIMIT 20
        ");
        $stmt->bind_param("sss", $searchTerm, $searchTerm, $searchTerm);
        $stmt->execute();
        $result = $stmt->get_result();

        $results = [];
        while ($row = $result->fetch_assoc()) {
            $results[] = $row;
        }
        $stmt->close();

        sendSuccess(['results' => $results, 'query' => $query]);
        break;

    default:
        sendError('Invalid action. Valid: browse, trending, search', 400);
        break;
}

$conn->close();
?>
