<?php
/**
 * CreativePort — Analytics API
 * Track portfolio views and provide analytics data
 */
require_once __DIR__ . '/config.php';

$action = $_GET['action'] ?? (getRequestBody()['action'] ?? '');

switch ($action) {

    // ─── TRACK A VIEW ──────────────────────────────────────
    case 'track':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') sendError('Method not allowed', 405);
        $data = getRequestBody();
        $portfolioId = intval($data['portfolio_id'] ?? 0);

        if (!$portfolioId) sendError('Portfolio ID is required.');

        // Don't track owner's own views
        $currentUser = getCurrentUser();
        if ($currentUser) {
            $stmt = $conn->prepare("SELECT user_id FROM portfolios WHERE id = ?");
            $stmt->bind_param("i", $portfolioId);
            $stmt->execute();
            $result = $stmt->get_result()->fetch_assoc();
            $stmt->close();
            if ($result && $result['user_id'] == $currentUser['id']) {
                sendSuccess([], 'Own view not tracked.');
            }
        }

        $viewerIp = $_SERVER['REMOTE_ADDR'] ?? '';
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $referrer = $_SERVER['HTTP_REFERER'] ?? '';

        $stmt = $conn->prepare("INSERT INTO portfolio_views (portfolio_id, viewer_ip, user_agent, referrer) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $portfolioId, $viewerIp, $userAgent, $referrer);
        $stmt->execute();
        $stmt->close();

        sendSuccess([], 'View tracked.');
        break;

    // ─── PORTFOLIO STATS ───────────────────────────────────
    case 'stats':
        $authUser = requireAuth();
        $portfolioId = intval($_GET['portfolio_id'] ?? 0);

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

        // Total views
        $stmt = $conn->prepare("SELECT COUNT(*) as total FROM portfolio_views WHERE portfolio_id = ?");
        $stmt->bind_param("i", $portfolioId);
        $stmt->execute();
        $total = $stmt->get_result()->fetch_assoc()['total'];
        $stmt->close();

        // Views last 7 days
        $stmt = $conn->prepare("SELECT COUNT(*) as recent FROM portfolio_views WHERE portfolio_id = ? AND viewed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)");
        $stmt->bind_param("i", $portfolioId);
        $stmt->execute();
        $recent = $stmt->get_result()->fetch_assoc()['recent'];
        $stmt->close();

        // Views last 30 days
        $stmt = $conn->prepare("SELECT COUNT(*) as monthly FROM portfolio_views WHERE portfolio_id = ? AND viewed_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)");
        $stmt->bind_param("i", $portfolioId);
        $stmt->execute();
        $monthly = $stmt->get_result()->fetch_assoc()['monthly'];
        $stmt->close();

        // Views per day (last 7 days)
        $stmt = $conn->prepare("
            SELECT DATE(viewed_at) as date, COUNT(*) as views 
            FROM portfolio_views 
            WHERE portfolio_id = ? AND viewed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(viewed_at) ORDER BY date
        ");
        $stmt->bind_param("i", $portfolioId);
        $stmt->execute();
        $result = $stmt->get_result();
        $dailyViews = [];
        while ($row = $result->fetch_assoc()) {
            $dailyViews[] = $row;
        }
        $stmt->close();

        sendSuccess([
            'total_views' => $total,
            'views_last_7_days' => $recent,
            'views_last_30_days' => $monthly,
            'daily_views' => $dailyViews
        ]);
        break;

    // ─── DASHBOARD STATS ───────────────────────────────────
    case 'dashboard':
        $authUser = requireAuth();

        // Total portfolios
        $stmt = $conn->prepare("SELECT COUNT(*) as total FROM portfolios WHERE user_id = ?");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $totalPortfolios = $stmt->get_result()->fetch_assoc()['total'];
        $stmt->close();

        // Published count
        $stmt = $conn->prepare("SELECT COUNT(*) as published FROM portfolios WHERE user_id = ? AND status = 'published'");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $publishedCount = $stmt->get_result()->fetch_assoc()['published'];
        $stmt->close();

        // Total views across all portfolios
        $stmt = $conn->prepare("
            SELECT COUNT(*) as total_views FROM portfolio_views pv
            JOIN portfolios p ON pv.portfolio_id = p.id
            WHERE p.user_id = ?
        ");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $totalViews = $stmt->get_result()->fetch_assoc()['total_views'];
        $stmt->close();

        // Average score
        $stmt = $conn->prepare("SELECT AVG(score) as avg_score FROM portfolios WHERE user_id = ?");
        $stmt->bind_param("i", $authUser['id']);
        $stmt->execute();
        $avgScore = round($stmt->get_result()->fetch_assoc()['avg_score'] ?? 0);
        $stmt->close();

        sendSuccess([
            'total_portfolios' => $totalPortfolios,
            'published_count' => $publishedCount,
            'draft_count' => $totalPortfolios - $publishedCount,
            'total_views' => $totalViews,
            'avg_score' => $avgScore
        ]);
        break;

    default:
        sendError('Invalid action. Valid: track, stats, dashboard', 400);
        break;
}

$conn->close();
?>
