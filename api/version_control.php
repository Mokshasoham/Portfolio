<?php
/**
 * Portfolio Version Control
 * Save and restore previous portfolio versions
 */

require_once 'config.php';

class PortfolioVersionControl {
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
    }
    
    /**
     * Create a new version (snapshot)
     */
    public function createVersion($portfolio_id, $version_name = '') {
        // Get current portfolio
        $stmt = $this->conn->prepare("
            SELECT content_json, status FROM portfolios WHERE id = ?
        ");
        $stmt->bind_param("i", $portfolio_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            return ['success' => false, 'error' => 'Portfolio not found'];
        }
        
        $portfolio = $result->fetch_assoc();
        
        // Create version record
        if (!$version_name) {
            $version_name = 'Version - ' . date('Y-m-d H:i:s');
        }
        
        $stmt = $this->conn->prepare("
            INSERT INTO portfolio_versions (portfolio_id, version_name, content_json, created_at)
            VALUES (?, ?, ?, NOW())
        ");
        $stmt->bind_param("iss", $portfolio_id, $version_name, $portfolio['content_json']);
        
        if ($stmt->execute()) {
            return [
                'success' => true,
                'version_id' => $stmt->insert_id,
                'message' => 'Version created successfully'
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to create version'];
    }
    
    /**
     * Get all versions of a portfolio
     */
    public function getVersions($portfolio_id) {
        $stmt = $this->conn->prepare("
            SELECT id, version_name, created_at, 
                   (SELECT COUNT(*) FROM portfolios WHERE id = ?) as is_current
            FROM portfolio_versions
            WHERE portfolio_id = ?
            ORDER BY created_at DESC
        ");
        $stmt->bind_param("ii", $portfolio_id, $portfolio_id);
        $stmt->execute();
        return $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
    }
    
    /**
     * Restore a previous version
     */
    public function restoreVersion($portfolio_id, $version_id) {
        // Get version content
        $stmt = $this->conn->prepare("
            SELECT content_json FROM portfolio_versions 
            WHERE id = ? AND portfolio_id = ?
        ");
        $stmt->bind_param("ii", $version_id, $portfolio_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            return ['success' => false, 'error' => 'Version not found'];
        }
        
        $version = $result->fetch_assoc();
        
        // Update portfolio with version content
        $stmt = $this->conn->prepare("
            UPDATE portfolios SET content_json = ? WHERE id = ?
        ");
        $stmt->bind_param("si", $version['content_json'], $portfolio_id);
        
        if ($stmt->execute()) {
            // Create backup of current version
            $this->createVersion($portfolio_id, 'Restored from version #' . $version_id);
            
            return [
                'success' => true,
                'message' => 'Portfolio restored successfully'
            ];
        }
        
        return ['success' => false, 'error' => 'Failed to restore version'];
    }
    
    /**
     * Delete a version
     */
    public function deleteVersion($version_id, $portfolio_id) {
        $stmt = $this->conn->prepare("
            DELETE FROM portfolio_versions 
            WHERE id = ? AND portfolio_id = ?
        ");
        $stmt->bind_param("ii", $version_id, $portfolio_id);
        
        $success = $stmt->execute();
        return [
            'success' => $success,
            'message' => $success ? 'Version deleted' : 'Failed to delete'
        ];
    }
}

// API Endpoint
if (isset($_SERVER['REQUEST_METHOD']) && ($_SERVER['REQUEST_METHOD'] === 'GET' || $_SERVER['REQUEST_METHOD'] === 'POST')) {
    $action = $_GET['action'] ?? '';
    $portfolio_id = intval($_GET['portfolio_id'] ?? $_POST['portfolio_id'] ?? 0);
    
    if ($portfolio_id <= 0) {
        http_response_code(400);
        echo json_encode(['success' => false, 'error' => 'Invalid portfolio ID']);
        exit;
    }
    
    $vc = new PortfolioVersionControl($conn);
    header('Content-Type: application/json');
    
    switch ($action) {
        case 'create_version':
            $name = $_POST['version_name'] ?? '';
            echo json_encode($vc->createVersion($portfolio_id, $name));
            break;
            
        case 'get_versions':
            echo json_encode([
                'success' => true,
                'versions' => $vc->getVersions($portfolio_id)
            ]);
            break;
            
        case 'restore_version':
            $version_id = intval($_POST['version_id'] ?? 0);
            echo json_encode($vc->restoreVersion($portfolio_id, $version_id));
            break;
            
        case 'delete_version':
            $version_id = intval($_POST['version_id'] ?? 0);
            echo json_encode($vc->deleteVersion($version_id, $portfolio_id));
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['success' => false, 'error' => 'Unknown action']);
    }
}
?>
