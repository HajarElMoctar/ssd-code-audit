<?php
// Security Configuration File

// Set secure session parameters
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_samesite', 'Strict');

// Security Headers
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('X-Content-Type-Options: nosniff');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' \'unsafe-eval\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\';');

// CSRF Protection Functions
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    if (!isset($_SESSION['csrf_token']) || $token !== $_SESSION['csrf_token']) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    return true;
}

// Input Sanitization Functions
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

function sanitizeOutput($data) {
    return htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
}



function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

// Database Security Functions
function prepareStatement($db, $query) {
    if (!$db instanceof Database) {
        throw new Exception('Invalid database connection');
    }
    return $db->executeQueryWithParams($query);
}

function executeStatement($db, $query, $params = []) {
    if (!$db instanceof Database) {
        throw new Exception('Invalid database connection');
    }
    return $db->executeQueryWithParams($query, $params);
}

// Error Handling
function handleError($errno, $errstr, $errfile, $errline) {
    error_log("Error [$errno] $errstr in $errfile on line $errline");
    if (ini_get('display_errors')) {
        echo "An error occurred. Please try again later.";
    }
    return true;
}

set_error_handler('handleError');

// Session Security
function secureSession() {
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }
    if (!isset($_SESSION['created'])) {
        $_SESSION['created'] = time();
    } else if (time() - $_SESSION['created'] > 1800) {
        session_regenerate_id(true);
        $_SESSION['created'] = time();
    }
}

// Rate Limiting
function checkRateLimit($ip, $limit = 100, $period = 3600) {
    $rateLimitFile = sys_get_temp_dir() . '/rate_limit_' . md5($ip) . '.txt';
    
    if (!file_exists($rateLimitFile)) {
        file_put_contents($rateLimitFile, json_encode([
            'count' => 1,
            'timestamp' => time()
        ]));
        return true;
    }
    
    $data = json_decode(file_get_contents($rateLimitFile), true);
    
    // Reset if period has passed
    if (time() - $data['timestamp'] > $period) {
        file_put_contents($rateLimitFile, json_encode([
            'count' => 1,
            'timestamp' => time()
        ]));
        return true;
    }
    
    // Check if limit exceeded
    if ($data['count'] >= $limit) {
        return false;
    }
    
    // Increment counter
    $data['count']++;
    file_put_contents($rateLimitFile, json_encode($data));
    return true;
} 