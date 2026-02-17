<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'error.log'); // Must be protected from external access
ini_set('memory_limit', '256M');
ini_set('max_execution_time', 30);

define('DB_FILE', 'messenger.db'); // Must be protected from external access
define('APP_NAME', 'liveto.chat');
define('UPLOAD_DIR', 'uploads/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024);
define('MAX_IMAGE_SIZE', 5 * 1024 * 1024);
define('RATE_LIMIT_MESSAGES', 10);
define('RATE_LIMIT_REGISTRATIONS', 3);
define('BCRYPT_COST', 12);
define('TURNSTILE_SITE_KEY', ''); // Cloudflare captcha
define('TURNSTILE_SECRET_KEY', ''); // Cloudflare captcha
define('ENCRYPTION_KEY', ''); // Database encryption key
define('CACHE_ENABLED', true);
define('CACHE_TTL', 300);
define('SEARCH_CACHE_TTL', 60);
define('MAX_SEARCH_RESULTS', 50);
define('WEBSOCKET_ENABLED', false);
define('ALLOWED_IMAGE_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
define('ALLOWED_FILE_TYPES', ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain']);

if (!file_exists(UPLOAD_DIR)) {
    mkdir(UPLOAD_DIR, 0755, true);
}

class Cache {
    private static $store = [];
    private static $timestamps = [];
    private static $maxItems = 1000;
    
    public static function get($key) {
        if (!CACHE_ENABLED) return null;
        
        if (isset(self::$store[$key]) && isset(self::$timestamps[$key])) {
            if (time() - self::$timestamps[$key] < CACHE_TTL) {
                return self::$store[$key];
            }
            unset(self::$store[$key], self::$timestamps[$key]);
        }
        
        return null;
    }
    
    public static function set($key, $value) {
        if (!CACHE_ENABLED) return;
        
        if (count(self::$store) >= self::$maxItems) {
            asort(self::$timestamps);
            $keysToRemove = array_slice(array_keys(self::$timestamps), 0, 100);
            foreach ($keysToRemove as $oldKey) {
                unset(self::$store[$oldKey], self::$timestamps[$oldKey]);
            }
        }
        
        self::$store[$key] = $value;
        self::$timestamps[$key] = time();
    }
    
    public static function clear($prefix = null) {
        if ($prefix === null) {
            self::$store = [];
            self::$timestamps = [];
        } else {
            foreach (array_keys(self::$store) as $key) {
                if (strpos($key, $prefix) === 0) {
                    unset(self::$store[$key], self::$timestamps[$key]);
                }
            }
        }
    }
    
    public static function remember($key, $callback, $ttl = null) {
        $value = self::get($key);
        if ($value !== null) {
            return $value;
        }
        
        $value = $callback();
        self::set($key, $value);
        return $value;
    }
}

class Encryption {
    private static $key;
    private static $method = 'aes-256-gcm';
    
    public static function init($key) {
        self::$key = hash('sha256', $key, true);
    }
    
    public static function encrypt($data) {
        if (empty($data)) return '';
        
        $ivlen = openssl_cipher_iv_length(self::$method);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $tag = '';
        
        $encrypted = openssl_encrypt(
            $data,
            self::$method,
            self::$key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            16
        );
        
        if ($encrypted === false) {
            error_log('Encryption failed: ' . openssl_error_string());
            throw new Exception('Encryption failed');
        }
        
        return base64_encode($iv . $tag . $encrypted);
    }
    
    public static function decrypt($data) {
        if (empty($data)) return '';
        
        $decoded = base64_decode($data);
        if ($decoded === false) return $data;
        
        $ivlen = openssl_cipher_iv_length(self::$method);
        
        if (strlen($decoded) < $ivlen + 16) {
            return $data;
        }
        
        $iv = substr($decoded, 0, $ivlen);
        $tag = substr($decoded, $ivlen, 16);
        $encrypted = substr($decoded, $ivlen + 16);
        
        $decrypted = openssl_decrypt(
            $encrypted,
            self::$method,
            self::$key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($decrypted === false) {
            error_log('Decryption failed: ' . openssl_error_string());
            return $data;
        }
        
        return $decrypted;
    }
    
    public static function encryptForSearch($data) {
        return hash('sha256', self::$key . $data);
    }
    
    public static function encryptForPrefix($data) {
        return substr(hash('sha256', self::$key . $data), 0, 8);
    }
}

Encryption::init(ENCRYPTION_KEY);

class Security {
    private static $rateLimitCache = [];
    private static $maxRequestsPerSecond = 50;
    
    public static function checkServerLoad() {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            if ($load[0] > 10) {
                http_response_code(503);
                header('Retry-After: 30');
                die(json_encode(['error' => 'Server is busy, please try again later']));
            }
        }
        return true;
    }
    
    public static function sanitizeInput($data) {
        if (is_array($data)) {
            return array_map([self::class, 'sanitizeInput'], $data);
        }
        return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
    }
    
    public static function generateCSRFToken() {
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
    
    public static function validateCSRFToken($token) {
        return hash_equals($_SESSION['csrf_token'] ?? '', $token);
    }
    
    public static function verifyTurnstile($token) {
        if (TURNSTILE_SECRET_KEY === '1x0000000000000000000000000000000AA') {
            return true;
        }
        
        $cacheKey = 'turnstile_' . md5($token);
        $cached = Cache::get($cacheKey);
        if ($cached !== null) {
            return $cached;
        }
        
        // Получаем реальный IP клиента с учетом Cloudflare
        $clientIP = self::getClientIP();
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query([
                'secret' => TURNSTILE_SECRET_KEY,
                'response' => $token,
                'remoteip' => $clientIP
            ]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3
        ]);
        
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            error_log("Turnstile error: $error");
            return false;
        }
        
        $data = json_decode($response, true);
        $result = $data['success'] ?? false;
        
        Cache::set($cacheKey, $result);
        
        return $result;
    }
    
    public static function checkRateLimit($action, $identifier, $limit, $period = 60) {
        $key = $action . '_' . $identifier;
        $now = time();
        
        if (!isset(self::$rateLimitCache[$key])) {
            self::$rateLimitCache[$key] = [];
        }
        
        self::$rateLimitCache[$key] = array_filter(
            self::$rateLimitCache[$key],
            function($timestamp) use ($now, $period) {
                return $timestamp > $now - $period;
            }
        );
        
        if (count(self::$rateLimitCache[$key]) >= $limit) {
            return false;
        }
        
        self::$rateLimitCache[$key][] = $now;
        return true;
    }
    
    public static function checkBruteforce($ip, $username) {
        $key = 'bruteforce_' . $ip . '_' . $username;
        $attempts = $_SESSION[$key] ?? ['count' => 0, 'first_attempt' => time()];
        
        if (time() - $attempts['first_attempt'] > 900) {
            $attempts = ['count' => 0, 'first_attempt' => time()];
        }
        
        $attempts['count']++;
        $_SESSION[$key] = $attempts;
        
        return $attempts['count'] <= 5;
    }
    
    public static function validateFile($file, $type = 'any') {
        if ($file['error'] !== UPLOAD_ERR_OK) {
            return ['error' => 'Ошибка загрузки файла'];
        }
        
        $maxSize = ($type === 'image') ? MAX_IMAGE_SIZE : MAX_FILE_SIZE;
        
        if ($file['size'] > $maxSize) {
            return ['error' => "Файл слишком большой. Максимальный размер: " . ($maxSize / 1024 / 1024) . "MB"];
        }
        
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        if ($type === 'image') {
            if (!in_array($mimeType, ALLOWED_IMAGE_TYPES)) {
                return ['error' => 'Недопустимый тип изображения'];
            }
            
            $imageInfo = getimagesize($file['tmp_name']);
            if (!$imageInfo) {
                return ['error' => 'Файл не является изображением'];
            }
            
            if ($mimeType === 'image/svg+xml') {
                $content = file_get_contents($file['tmp_name']);
                if (preg_match('/<script|onload|onerror|javascript:/i', $content)) {
                    return ['error' => 'SVG содержит потенциально опасный код'];
                }
            }
        } else {
            if (!in_array($mimeType, ALLOWED_FILE_TYPES)) {
                return ['error' => 'Недопустимый тип файла'];
            }
        }
        
        $content = file_get_contents($file['tmp_name']);
        $dangerousPatterns = [
            '/<\?php/i',
            '/<script/i',
            '/eval\(/i',
            '/base64_decode/i',
            '/system\(/i',
            '/exec\(/i',
            '/shell_exec\(/i',
            '/passthru\(/i',
            '/popen\(/i',
            '/proc_open\(/i',
            '/pcntl_exec\(/i'
        ];
        
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $content)) {
                return ['error' => 'Файл содержит подозрительный код'];
            }
        }
        
        return ['success' => true, 'mime_type' => $mimeType];
    }
    
    public static function processUpload($file, $type = 'any') {
        $validation = self::validateFile($file, $type);
        if (isset($validation['error'])) {
            return $validation;
        }
        
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $safeExtension = preg_replace('/[^a-zA-Z0-9]/', '', $extension);
        $filename = bin2hex(random_bytes(16)) . '_' . time() . '.' . $safeExtension;
        $filepath = UPLOAD_DIR . $filename;
        
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            chmod($filepath, 0644);
            
            if ($type === 'image' && $file['size'] > 1024 * 1024) {
                self::compressImage($filepath, $filepath, 80);
            }
            
            return [
                'success' => true,
                'filename' => $filename,
                'path' => $filepath,
                'size' => $file['size'],
                'original_name' => $file['name'],
                'mime_type' => $validation['mime_type']
            ];
        }
        
        return ['error' => 'Ошибка сохранения файла'];
    }
    
    private static function compressImage($source, $destination, $quality) {
        $info = getimagesize($source);
        
        switch ($info['mime']) {
            case 'image/jpeg':
                $image = imagecreatefromjpeg($source);
                imagejpeg($image, $destination, $quality);
                break;
            case 'image/png':
                $image = imagecreatefrompng($source);
                imagepng($image, $destination, round(9 * $quality / 100));
                break;
            case 'image/gif':
                $image = imagecreatefromgif($source);
                imagegif($image, $destination);
                break;
            case 'image/webp':
                $image = imagecreatefromwebp($source);
                imagewebp($image, $destination, $quality);
                break;
        }
        
        if (isset($image)) {
            imagedestroy($image);
        }
    }
    
    public static function getEncryptedIP() {
        $ip = self::getClientIP();
        return Encryption::encrypt($ip);
    }
    
    public static function getClientIP() {
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        
        $proxyHeaders = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED',
            'HTTP_FORWARDED_FOR',
            'HTTP_FORWARDED'
        ];
        
        foreach ($proxyHeaders as $header) {
            if (isset($_SERVER[$header])) {
                $ipList = explode(',', $_SERVER[$header]);
                $ip = trim($ipList[0]);
                
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
                
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        if (isset($_SERVER['REMOTE_ADDR'])) {
            $ip = $_SERVER['REMOTE_ADDR'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
            return $ip;
        }
        
        return '0.0.0.0';
    }
    
    public static function validatePassword($password) {
        if (strlen($password) < 8) {
            return 'Пароль должен быть не менее 8 символов';
        }
        
        if (!preg_match('/[A-Z]/', $password)) {
            return 'Пароль должен содержать хотя бы одну заглавную букву';
        }
        
        if (!preg_match('/[a-z]/', $password)) {
            return 'Пароль должен содержать хотя бы одну строчную букву';
        }
        
        if (!preg_match('/[0-9]/', $password)) {
            return 'Пароль должен содержать хотя бы одну цифру';
        }
        
        $commonPasswords = ['password', '12345678', 'qwerty123', 'admin123'];
        if (in_array(strtolower($password), $commonPasswords)) {
            return 'Пароль слишком простой';
        }
        
        return true;
    }
    
    public static function validateUsername($username) {
        if (strlen($username) < 3 || strlen($username) > 30) {
            return 'Имя пользователя должно быть от 3 до 30 символов';
        }
        
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) {
            return 'Имя пользователя может содержать только буквы, цифры и _';
        }
        
        return true;
    }
}

class MessengerDB {
    private $db;
    private $stmtCache = [];
    private $transactionLevel = 0;
    private $maxRetries = 5;
    private $retryDelay = 100000;
    
    public function __construct() {
        if (file_exists(DB_FILE)) {
            chmod(DB_FILE, 0600);
        }
        
        $this->db = new SQLite3(DB_FILE);
        
        if (file_exists(DB_FILE)) {
            chmod(DB_FILE, 0600);
        }
        
        $this->db->exec("PRAGMA foreign_keys = ON;");
        $this->db->exec("PRAGMA journal_mode = WAL;");
        $this->db->exec("PRAGMA synchronous = NORMAL;");
        $this->db->exec("PRAGMA cache_size = 10000;");
        $this->db->exec("PRAGMA temp_store = MEMORY;");
        $this->db->exec("PRAGMA busy_timeout = 10000;");
        $this->db->exec("PRAGMA journal_size_limit = 67108864;");
        $this->db->exec("PRAGMA mmap_size = 134217728;");
        
        $this->initTables();
    }
    
    private function executeWithRetry($callback, $customMaxRetries = null) {
        $retries = $customMaxRetries ?? $this->maxRetries;
        
        for ($i = 0; $i < $retries; $i++) {
            try {
                return $callback();
            } catch (Exception $e) {
                $isLocked = strpos($e->getMessage(), 'database is locked') !== false ||
                           strpos($e->getMessage(), 'locked') !== false;
                
                if (!$isLocked || $i === $retries - 1) {
                    throw $e;
                }
                
                $delay = $this->retryDelay * pow(2, $i);
                usleep($delay);
                
                error_log("Database locked, retry " . ($i + 1) . " after " . ($delay/1000) . "ms");
            }
        }
    }
    
    public function exec($sql) {
        return $this->executeWithRetry(function() use ($sql) {
            return $this->db->exec($sql);
        });
    }
    
    public function query($sql, $params = []) {
        return $this->executeWithRetry(function() use ($sql, $params) {
            $cacheKey = 'query_' . md5($sql . serialize($params));
            
            return Cache::remember($cacheKey, function() use ($sql, $params) {
                $stmt = $this->prepare($sql);
                foreach ($params as $key => $value) {
                    $stmt->bindValue($key, $value);
                }
                
                $result = $stmt->execute();
                $rows = [];
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $rows[] = $row;
                }
                
                return $rows;
            }, CACHE_TTL);
        });
    }
    
    public function querySingle($sql, $params = []) {
        $result = $this->query($sql, $params);
        return !empty($result) ? $result[0] : null;
    }
    
    public function queryValue($sql, $params = []) {
        $result = $this->query($sql, $params);
        if (!empty($result) && !empty($result[0])) {
            return reset($result[0]);
        }
        return null;
    }
    
    public function insert($sql, $params = []) {
        return $this->executeWithRetry(function() use ($sql, $params) {
            $stmt = $this->prepare($sql);
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->execute();
            return $this->db->lastInsertRowID();
        });
    }
    
    public function execute($sql, $params = []) {
        return $this->executeWithRetry(function() use ($sql, $params) {
            $stmt = $this->prepare($sql);
            foreach ($params as $key => $value) {
                $stmt->bindValue($key, $value);
            }
            $stmt->execute();
            return $this->db->changes();
        });
    }
    
    public function prepare($query) {
        $key = md5($query);
        if (!isset($this->stmtCache[$key])) {
            $this->stmtCache[$key] = $this->db->prepare($query);
        } else {
            $this->stmtCache[$key]->reset();
            $this->stmtCache[$key]->clear();
        }
        return $this->stmtCache[$key];
    }
    
    public function beginTransaction() {
        if ($this->transactionLevel === 0) {
            $this->exec("BEGIN IMMEDIATE TRANSACTION");
        }
        $this->transactionLevel++;
        return true;
    }
    
    public function commitTransaction() {
        $this->transactionLevel--;
        if ($this->transactionLevel === 0) {
            return $this->exec("COMMIT");
        }
        return true;
    }
    
    public function rollbackTransaction() {
        $this->transactionLevel = 0;
        return $this->exec("ROLLBACK");
    }
    
    public function transaction($callback) {
        try {
            $this->beginTransaction();
            $result = $callback();
            $this->commitTransaction();
            return $result;
        } catch (Exception $e) {
            $this->rollbackTransaction();
            throw $e;
        }
    }
    
    private function initTables() {
        $this->exec("
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username_encrypted TEXT NOT NULL,
                username_hash TEXT UNIQUE NOT NULL,
                username_prefix TEXT NOT NULL,
                email_encrypted TEXT,
                email_hash TEXT UNIQUE,
                password TEXT NOT NULL,
                avatar TEXT,
                status TEXT DEFAULT 'offline',
                theme TEXT DEFAULT 'light',
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address_encrypted TEXT,
                failed_attempts INTEGER DEFAULT 0,
                locked_until DATETIME
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS friend_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user INTEGER,
                to_user INTEGER,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(from_user) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(to_user) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(from_user, to_user)
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name_encrypted TEXT NOT NULL,
                name_hash TEXT UNIQUE NOT NULL,
                name_prefix TEXT NOT NULL,
                description_encrypted TEXT,
                avatar TEXT,
                creator_id INTEGER,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(creator_id) REFERENCES users(id) ON DELETE SET NULL
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER,
                user_id INTEGER,
                role TEXT DEFAULT 'member',
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY(group_id, user_id)
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS group_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER,
                from_user INTEGER,
                to_user INTEGER,
                status TEXT DEFAULT 'pending',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY(from_user) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(to_user) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(group_id, to_user)
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                group_id INTEGER,
                message_encrypted TEXT,
                message_hash TEXT,
                message_prefix TEXT,
                type TEXT DEFAULT 'text',
                file_name TEXT,
                file_path TEXT,
                file_size INTEGER,
                file_type TEXT,
                is_edited BOOLEAN DEFAULT 0,
                reply_to INTEGER,
                sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip_address_encrypted TEXT,
                FOREIGN KEY(sender_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(receiver_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
                FOREIGN KEY(reply_to) REFERENCES messages(id) ON DELETE SET NULL
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS reactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id INTEGER,
                user_id INTEGER,
                reaction TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(message_id, user_id, reaction)
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS read_receipts (
                message_id INTEGER,
                user_id INTEGER,
                read_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY(message_id, user_id)
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS rate_limits (
                ip_address_encrypted TEXT,
                action_type TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(ip_address_encrypted, action_type, created_at)
            );
        ");
        
        $this->exec("
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                session_token TEXT UNIQUE,
                ip_address_encrypted TEXT,
                user_agent_encrypted TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        ");
        
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_sent_at ON messages(sent_at);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id) WHERE receiver_id IS NOT NULL;");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id) WHERE group_id IS NOT NULL;");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_users_hash ON users(username_hash, email_hash);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_users_prefix ON users(username_prefix);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_created ON rate_limits(created_at);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_group_invites_to ON group_invites(to_user, status);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_friend_requests_status ON friend_requests(from_user, to_user, status);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON user_sessions(session_token);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_user_sessions_expires ON user_sessions(expires_at);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_prefix ON messages(message_prefix);");
        
        $this->migrateExistingData();
    }
    
    private function migrateExistingData() {
        try {
            $result = $this->query("PRAGMA table_info(users)");
            $columns = array_column($result, 'name');
            
            if (!in_array('username_prefix', $columns)) {
                error_log("Adding username_prefix column to users table...");
                
                $this->transaction(function() {
                    $this->exec("ALTER TABLE users ADD COLUMN username_prefix TEXT");
                    $this->exec("CREATE INDEX IF NOT EXISTS idx_users_prefix ON users(username_prefix)");
                    
                    $users = $this->query("SELECT id, username_encrypted FROM users");
                    foreach ($users as $row) {
                        $username = Encryption::decrypt($row['username_encrypted']);
                        $prefix = Encryption::encryptForPrefix($username);
                        
                        $this->execute(
                            "UPDATE users SET username_prefix = :prefix WHERE id = :id",
                            [':prefix' => $prefix, ':id' => $row['id']]
                        );
                    }
                });
            }
            
            if (!in_array('ip_address_encrypted', $columns)) {
                error_log("Adding ip_address_encrypted column to users table...");
                
                $this->transaction(function() {
                    $this->exec("ALTER TABLE users ADD COLUMN ip_address_encrypted TEXT");
                    
                    $users = $this->query("SELECT id, ip_address FROM users WHERE ip_address IS NOT NULL");
                    foreach ($users as $row) {
                        $encryptedIP = Encryption::encrypt($row['ip_address']);
                        $this->execute(
                            "UPDATE users SET ip_address_encrypted = :enc WHERE id = :id",
                            [':enc' => $encryptedIP, ':id' => $row['id']]
                        );
                    }
                    
                    $this->exec("ALTER TABLE users DROP COLUMN ip_address");
                });
            }
            
            $result = $this->query("PRAGMA table_info(groups)");
            $columns = array_column($result, 'name');
            
            if (!in_array('name_prefix', $columns)) {
                error_log("Adding name_prefix column to groups table...");
                
                $this->transaction(function() {
                    $this->exec("ALTER TABLE groups ADD COLUMN name_prefix TEXT");
                    
                    $groups = $this->query("SELECT id, name_encrypted FROM groups");
                    foreach ($groups as $row) {
                        $name = Encryption::decrypt($row['name_encrypted']);
                        $prefix = Encryption::encryptForPrefix($name);
                        
                        $this->execute(
                            "UPDATE groups SET name_prefix = :prefix WHERE id = :id",
                            [':prefix' => $prefix, ':id' => $row['id']]
                        );
                    }
                });
            }
            
            $result = $this->query("PRAGMA table_info(rate_limits)");
            $columns = array_column($result, 'name');
            
            if (!in_array('ip_address_encrypted', $columns)) {
                error_log("Migrating rate_limits table to encrypted IPs...");
                
                $this->transaction(function() {
                    $this->exec("
                        CREATE TABLE rate_limits_new (
                            ip_address_encrypted TEXT,
                            action_type TEXT,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            PRIMARY KEY(ip_address_encrypted, action_type, created_at)
                        )
                    ");
                    
                    $oldData = $this->query("SELECT ip_address, action_type, created_at FROM rate_limits");
                    foreach ($oldData as $row) {
                        $encryptedIP = Encryption::encrypt($row['ip_address']);
                        $this->execute(
                            "INSERT INTO rate_limits_new (ip_address_encrypted, action_type, created_at) VALUES (:ip, :action, :created)",
                            [':ip' => $encryptedIP, ':action' => $row['action_type'], ':created' => $row['created_at']]
                        );
                    }
                    
                    $this->exec("DROP TABLE rate_limits");
                    $this->exec("ALTER TABLE rate_limits_new RENAME TO rate_limits");
                    
                    $this->exec("CREATE INDEX IF NOT EXISTS idx_rate_limits_created ON rate_limits(created_at);");
                });
            }
            
            $result = $this->query("PRAGMA table_info(user_sessions)");
            $columns = array_column($result, 'name');
            
            if (!in_array('ip_address_encrypted', $columns)) {
                error_log("Migrating user_sessions table to encrypted IPs...");
                
                $this->transaction(function() {
                    $this->exec("ALTER TABLE user_sessions ADD COLUMN ip_address_encrypted TEXT");
                    
                    $sessions = $this->query("SELECT id, ip_address FROM user_sessions WHERE ip_address IS NOT NULL");
                    foreach ($sessions as $row) {
                        $encryptedIP = Encryption::encrypt($row['ip_address']);
                        $this->execute(
                            "UPDATE user_sessions SET ip_address_encrypted = :enc WHERE id = :id",
                            [':enc' => $encryptedIP, ':id' => $row['id']]
                        );
                    }
                    
                    $this->exec("ALTER TABLE user_sessions DROP COLUMN ip_address");
                });
            }
            
            if (!in_array('user_agent_encrypted', $columns)) {
                error_log("Adding user_agent_encrypted column to user_sessions table...");
                
                $this->transaction(function() {
                    $this->exec("ALTER TABLE user_sessions ADD COLUMN user_agent_encrypted TEXT");
                    
                    $sessions = $this->query("SELECT id, user_agent FROM user_sessions WHERE user_agent IS NOT NULL");
                    foreach ($sessions as $row) {
                        $encryptedUA = Encryption::encrypt($row['user_agent']);
                        $this->execute(
                            "UPDATE user_sessions SET user_agent_encrypted = :enc WHERE id = :id",
                            [':enc' => $encryptedUA, ':id' => $row['id']]
                        );
                    }
                    
                    $this->exec("ALTER TABLE user_sessions DROP COLUMN user_agent");
                });
            }
            
            $result = $this->query("PRAGMA table_info(messages)");
            $columns = array_column($result, 'name');
            
            if (!in_array('ip_address_encrypted', $columns)) {
                error_log("Migrating messages table to encrypted IPs...");
                
                $this->transaction(function() {
                    $this->exec("ALTER TABLE messages ADD COLUMN ip_address_encrypted TEXT");
                    
                    $messages = $this->query("SELECT id, ip_address FROM messages WHERE ip_address IS NOT NULL");
                    foreach ($messages as $row) {
                        $encryptedIP = Encryption::encrypt($row['ip_address']);
                        $this->execute(
                            "UPDATE messages SET ip_address_encrypted = :enc WHERE id = :id",
                            [':enc' => $encryptedIP, ':id' => $row['id']]
                        );
                    }
                    
                    $this->exec("ALTER TABLE messages DROP COLUMN ip_address");
                });
            }
            
        } catch (Exception $e) {
            error_log("Migration error: " . $e->getMessage());
        }
    }
    
    public function getDb() {
        return $this->db;
    }
    
    public function searchUsers($query, $currentUserId, $limit = 20) {
        $prefix = Encryption::encryptForPrefix($query);
        
        $cacheKey = 'search_' . $prefix . '_' . $currentUserId;
        
        return Cache::remember($cacheKey, function() use ($prefix, $query, $currentUserId, $limit) {
            $candidates = $this->query(
                "SELECT id, username_encrypted, status, avatar 
                 FROM users 
                 WHERE id != :user_id 
                   AND username_prefix = :prefix
                 ORDER BY last_seen DESC
                 LIMIT :pre_limit",
                [
                    ':user_id' => $currentUserId,
                    ':prefix' => $prefix,
                    ':pre_limit' => $limit * 3
                ]
            );
            
            $result = [];
            $queryLower = strtolower($query);
            
            foreach ($candidates as $row) {
                $username = Encryption::decrypt($row['username_encrypted']);
                if (stripos($username, $queryLower) !== false) {
                    $row['username'] = $username;
                    unset($row['username_encrypted']);
                    $result[] = $row;
                    
                    if (count($result) >= $limit) {
                        break;
                    }
                }
            }
            
            return $result;
        }, SEARCH_CACHE_TTL);
    }
    
    public function addReadReceipt($messageId, $userId) {
        try {
            $this->execute(
                "INSERT OR IGNORE INTO read_receipts (message_id, user_id) VALUES (:msg_id, :user_id)",
                [':msg_id' => $messageId, ':user_id' => $userId]
            );
            
            return (int)$this->queryValue(
                "SELECT COUNT(*) as count FROM read_receipts WHERE message_id = :msg_id",
                [':msg_id' => $messageId]
            );
        } catch (Exception $e) {
            error_log("Error adding read receipt: " . $e->getMessage());
            return 0;
        }
    }
    
    public function getGroupReadCounts($groupId, $messageIds) {
        if (empty($messageIds)) return [];
        
        $placeholders = implode(',', array_fill(0, count($messageIds), '?'));
        $params = [];
        foreach ($messageIds as $i => $id) {
            $params[$i + 1] = $id;
        }
        
        $results = $this->query(
            "SELECT message_id, COUNT(DISTINCT user_id) as count
             FROM read_receipts
             WHERE message_id IN ($placeholders)
             GROUP BY message_id",
            $params
        );
        
        $counts = [];
        foreach ($results as $row) {
            $counts[$row['message_id']] = $row['count'];
        }
        
        return $counts;
    }
    
    public function addRateLimit($ip, $action) {
        $encryptedIP = Encryption::encrypt($ip);
        
        return $this->execute(
            "INSERT INTO rate_limits (ip_address_encrypted, action_type) VALUES (:ip, :action)",
            [':ip' => $encryptedIP, ':action' => $action]
        );
    }
    
    public function checkRateLimit($ip, $action, $limit, $period = 3600) {
        $encryptedIP = Encryption::encrypt($ip);
        
        $count = $this->queryValue(
            "SELECT COUNT(*) as count FROM rate_limits 
             WHERE ip_address_encrypted = :ip AND action_type = :action 
             AND created_at > datetime('now', '-' || :period || ' seconds')",
            [
                ':ip' => $encryptedIP,
                ':action' => $action,
                ':period' => $period
            ]
        );
        
        return $count < $limit;
    }
}

$dbManager = new MessengerDB();
$db = $dbManager->getDb();

$db->exec("DELETE FROM rate_limits WHERE created_at < datetime('now', '-1 hour')");
$db->exec("DELETE FROM user_sessions WHERE expires_at < CURRENT_TIMESTAMP");

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; frame-src https://challenges.cloudflare.com;");

function getClientIP() {
    return Security::getClientIP();
}

function sendJsonResponse($data, $statusCode = 200) {
    http_response_code($statusCode);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

$clientIP = getClientIP();

Security::checkServerLoad();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = Security::sanitizeInput($_POST['action']);
    $user_id = $_SESSION['user_id'] ?? null;
    
    if (!in_array($action, ['login', 'register']) && !Security::validateCSRFToken($_POST['csrf_token'] ?? '')) {
        sendJsonResponse(['error' => 'Недействительный CSRF токен']);
    }
    
    try {
        switch($action) {
            case 'login':
                $username = $_POST['username'] ?? '';
                $password = $_POST['password'] ?? '';
                $cfTurnstileToken = $_POST['cf-turnstile-response'] ?? '';
                
                if (!Security::verifyTurnstile($cfTurnstileToken)) {
                    sendJsonResponse(['error' => 'Пожалуйста, подтвердите, что вы не робот']);
                }
                
                if (!Security::checkBruteforce($clientIP, $username)) {
                    sendJsonResponse(['error' => 'Слишком много попыток. Попробуйте позже.']);
                }
                
                if (!Security::checkRateLimit('login', $clientIP, 10, 300)) {
                    sendJsonResponse(['error' => 'Слишком много попыток входа. Подождите 5 минут.']);
                }
                
                $usernameHash = Encryption::encryptForSearch($username);
                
                $stmt = $dbManager->prepare("
                    SELECT * FROM users 
                    WHERE username_hash = :username_hash 
                       OR email_hash = :username_hash
                ");
                $stmt->bindValue(':username_hash', $usernameHash);
                $result = $stmt->execute();
                $user = $result->fetchArray(SQLITE3_ASSOC);
                
                if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
                    sendJsonResponse(['error' => 'Аккаунт заблокирован. Попробуйте позже.']);
                }
                
                if ($user && password_verify($password, $user['password'])) {
                    if (password_needs_rehash($user['password'], PASSWORD_BCRYPT, ['cost' => BCRYPT_COST])) {
                        $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
                        $stmt = $dbManager->prepare("UPDATE users SET password = :password WHERE id = :id");
                        $stmt->bindValue(':password', $newHash);
                        $stmt->bindValue(':id', $user['id']);
                        $stmt->execute();
                    }
                    
                    $stmt = $dbManager->prepare("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = :id");
                    $stmt->bindValue(':id', $user['id']);
                    $stmt->execute();
                    
                    session_regenerate_id(true);
                    
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = Encryption::decrypt($user['username_encrypted']);
                    $_SESSION['login_time'] = time();
                    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                    $_SESSION['ip_address'] = $clientIP;
                    
                    $sessionToken = bin2hex(random_bytes(32));
                    $encryptedIP = Encryption::encrypt($clientIP);
                    $encryptedUA = Encryption::encrypt($_SERVER['HTTP_USER_AGENT'] ?? '');
                    
                    $stmt = $dbManager->prepare("
                        INSERT INTO user_sessions (user_id, session_token, ip_address_encrypted, user_agent_encrypted, expires_at) 
                        VALUES (:user_id, :token, :ip, :ua, datetime('now', '+7 days'))
                    ");
                    $stmt->bindValue(':user_id', $user['id']);
                    $stmt->bindValue(':token', $sessionToken);
                    $stmt->bindValue(':ip', $encryptedIP);
                    $stmt->bindValue(':ua', $encryptedUA);
                    $stmt->execute();
                    
                    $_SESSION['session_token'] = $sessionToken;
                    
                    $encryptedIP = Encryption::encrypt($clientIP);
                    $stmt = $dbManager->prepare("UPDATE users SET status = 'online', last_seen = CURRENT_TIMESTAMP, ip_address_encrypted = :ip WHERE id = :id");
                    $stmt->bindValue(':ip', $encryptedIP);
                    $stmt->bindValue(':id', $user['id']);
                    $stmt->execute();
                    
                    unset($user['password']);
                    
                    $user['username'] = Encryption::decrypt($user['username_encrypted']);
                    if ($user['email_encrypted']) {
                        $user['email'] = Encryption::decrypt($user['email_encrypted']);
                    }
                    
                    unset($user['username_encrypted'], $user['email_encrypted'], $user['username_hash'], $user['email_hash'], $user['username_prefix'], $user['ip_address_encrypted']);
                    
                    sendJsonResponse(['success' => true, 'user' => $user, 'csrf_token' => Security::generateCSRFToken()]);
                } else {
                    if ($user) {
                        $stmt = $dbManager->prepare("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = :id");
                        $stmt->bindValue(':id', $user['id']);
                        $stmt->execute();
                        
                        $stmt = $dbManager->prepare("SELECT failed_attempts FROM users WHERE id = :id");
                        $stmt->bindValue(':id', $user['id']);
                        $result = $stmt->execute();
                        $attempts = $result->fetchArray(SQLITE3_ASSOC);
                        
                        if ($attempts['failed_attempts'] >= 5) {
                            $stmt = $dbManager->prepare("UPDATE users SET locked_until = datetime('now', '+15 minutes') WHERE id = :id");
                            $stmt->bindValue(':id', $user['id']);
                            $stmt->execute();
                        }
                    }
                    
                    sendJsonResponse(['error' => 'Неверный логин или пароль']);
                }
                break;
                
            case 'register':
                $username = trim($_POST['username'] ?? '');
                $email = trim($_POST['email'] ?? '');
                $password = $_POST['password'] ?? '';
                $cfTurnstileToken = $_POST['cf-turnstile-response'] ?? '';
                
                if (!Security::verifyTurnstile($cfTurnstileToken)) {
                    sendJsonResponse(['error' => 'Пожалуйста, подтвердите, что вы не робот']);
                }
                
                $usernameValidation = Security::validateUsername($username);
                if ($usernameValidation !== true) {
                    sendJsonResponse(['error' => $usernameValidation]);
                }
                
                $passwordValidation = Security::validatePassword($password);
                if ($passwordValidation !== true) {
                    sendJsonResponse(['error' => $passwordValidation]);
                }
                
                if ($email && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    sendJsonResponse(['error' => 'Неверный формат email']);
                }
                
                if (!$dbManager->checkRateLimit($clientIP, 'register', RATE_LIMIT_REGISTRATIONS, 3600)) {
                    sendJsonResponse(['error' => 'Слишком много регистраций с вашего IP. Попробуйте позже.']);
                }
                
                $usernameEncrypted = Encryption::encrypt($username);
                $usernameHash = Encryption::encryptForSearch($username);
                $usernamePrefix = Encryption::encryptForPrefix($username);
                
                $emailEncrypted = $email ? Encryption::encrypt($email) : null;
                $emailHash = $email ? Encryption::encryptForSearch($email) : null;
                
                $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
                
                $encryptedIP = Encryption::encrypt($clientIP);
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        INSERT INTO users (username_encrypted, username_hash, username_prefix, email_encrypted, email_hash, password, ip_address_encrypted) 
                        VALUES (:username_enc, :username_hash, :username_prefix, :email_enc, :email_hash, :password, :ip)
                    ");
                    $stmt->bindValue(':username_enc', $usernameEncrypted);
                    $stmt->bindValue(':username_hash', $usernameHash);
                    $stmt->bindValue(':username_prefix', $usernamePrefix);
                    $stmt->bindValue(':email_enc', $emailEncrypted);
                    $stmt->bindValue(':email_hash', $emailHash);
                    $stmt->bindValue(':password', $hashedPassword);
                    $stmt->bindValue(':ip', $encryptedIP);
                    $stmt->execute();
                    
                    $dbManager->addRateLimit($clientIP, 'register');
                    
                    $dbManager->commitTransaction();
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    
                    if (strpos($e->getMessage(), 'username_hash') !== false) {
                        sendJsonResponse(['error' => 'Имя пользователя уже занято']);
                    } else if (strpos($e->getMessage(), 'email_hash') !== false) {
                        sendJsonResponse(['error' => 'Email уже используется']);
                    } else {
                        error_log("Registration error: " . $e->getMessage());
                        sendJsonResponse(['error' => 'Ошибка регистрации']);
                    }
                }
                break;
                
            case 'search_users':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $query = trim($_POST['query'] ?? '');
                if (strlen($query) < 2) {
                    sendJsonResponse(['success' => true, 'users' => []]);
                }
                
                $users = $dbManager->searchUsers($query, $user_id, 20);
                
                $safeUsers = array_map(function($user) {
                    return [
                        'id' => $user['id'],
                        'username' => $user['username'],
                        'avatar' => $user['avatar'],
                        'status' => $user['status']
                    ];
                }, $users);
                
                sendJsonResponse(['success' => true, 'users' => $safeUsers]);
                break;
                
            case 'send_friend_request':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $to_user = (int)$_POST['user_id'];
                
                if ($to_user == $user_id) {
                    sendJsonResponse(['error' => 'Нельзя отправить запрос самому себе']);
                }
                
                $stmt = $dbManager->prepare("SELECT id FROM users WHERE id = :id");
                $stmt->bindValue(':id', $to_user);
                if (!$stmt->execute()->fetchArray()) {
                    sendJsonResponse(['error' => 'Пользователь не найден']);
                }
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        INSERT OR IGNORE INTO friend_requests (from_user, to_user) 
                        VALUES (:from, :to)
                    ");
                    $stmt->bindValue(':from', $user_id);
                    $stmt->bindValue(':to', $to_user);
                    $stmt->execute();
                    
                    if ($db->changes() > 0) {
                        $dbManager->commitTransaction();
                        Cache::clear('friend_requests');
                        sendJsonResponse(['success' => true]);
                    } else {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Запрос уже отправлен']);
                    }
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка отправки запроса']);
                }
                break;
                
            case 'get_friend_requests':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $requests = Cache::remember('friend_requests_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("
                        SELECT fr.*, u.username_encrypted, u.avatar 
                        FROM friend_requests fr
                        JOIN users u ON u.id = fr.from_user
                        WHERE fr.to_user = :user_id AND fr.status = 'pending'
                        ORDER BY fr.created_at DESC
                    ");
                    $stmt->bindValue(':user_id', $user_id);
                    $result = $stmt->execute();
                    
                    $requests = [];
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $row['username'] = Encryption::decrypt($row['username_encrypted']);
                        unset($row['username_encrypted']);
                        $requests[] = $row;
                    }
                    
                    return $requests;
                }, 30);
                
                sendJsonResponse(['success' => true, 'requests' => $requests]);
                break;
                
            case 'get_group_invites':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $invites = Cache::remember('group_invites_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("
                        SELECT gi.*, g.name_encrypted as group_name_enc, u.username_encrypted as inviter_name_enc
                        FROM group_invites gi
                        JOIN groups g ON g.id = gi.group_id
                        JOIN users u ON u.id = gi.from_user
                        WHERE gi.to_user = :user_id AND gi.status = 'pending'
                        ORDER BY gi.created_at DESC
                    ");
                    $stmt->bindValue(':user_id', $user_id);
                    $result = $stmt->execute();
                    
                    $invites = [];
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $row['group_name'] = Encryption::decrypt($row['group_name_enc']);
                        $row['inviter_name'] = Encryption::decrypt($row['inviter_name_enc']);
                        unset($row['group_name_enc'], $row['inviter_name_enc']);
                        $invites[] = $row;
                    }
                    
                    return $invites;
                }, 30);
                
                sendJsonResponse(['success' => true, 'invites' => $invites]);
                break;
                
            case 'respond_friend_request':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $request_id = (int)$_POST['request_id'];
                $accept = $_POST['accept'] === 'true';
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        UPDATE friend_requests 
                        SET status = :status, updated_at = CURRENT_TIMESTAMP 
                        WHERE id = :id AND to_user = :user_id AND status = 'pending'
                    ");
                    $stmt->bindValue(':status', $accept ? 'accepted' : 'rejected');
                    $stmt->bindValue(':id', $request_id);
                    $stmt->bindValue(':user_id', $user_id);
                    $stmt->execute();
                    
                    if ($db->changes() > 0) {
                        $dbManager->commitTransaction();
                        Cache::clear('friend_requests');
                        Cache::clear('friends_' . $user_id);
                        sendJsonResponse(['success' => true]);
                    } else {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Запрос не найден']);
                    }
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка обработки запроса']);
                }
                break;
                
            case 'respond_group_invite':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $invite_id = (int)$_POST['invite_id'];
                $accept = $_POST['accept'] === 'true';
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        SELECT * FROM group_invites 
                        WHERE id = :id AND to_user = :user_id AND status = 'pending'
                    ");
                    $stmt->bindValue(':id', $invite_id);
                    $stmt->bindValue(':user_id', $user_id);
                    $result = $stmt->execute();
                    $invite = $result->fetchArray(SQLITE3_ASSOC);
                    
                    if (!$invite) {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Приглашение не найдено']);
                    }
                    
                    $stmt = $dbManager->prepare("UPDATE group_invites SET status = :status WHERE id = :id");
                    $stmt->bindValue(':status', $accept ? 'accepted' : 'rejected');
                    $stmt->bindValue(':id', $invite_id);
                    $stmt->execute();
                    
                    if ($accept) {
                        $stmt = $dbManager->prepare("
                            INSERT OR IGNORE INTO group_members (group_id, user_id) 
                            VALUES (:group, :user)
                        ");
                        $stmt->bindValue(':group', $invite['group_id']);
                        $stmt->bindValue(':user', $user_id);
                        $stmt->execute();
                    }
                    
                    $dbManager->commitTransaction();
                    
                    Cache::clear('group_invites');
                    Cache::clear('groups_' . $user_id);
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка обработки приглашения']);
                }
                break;
                
            case 'get_friends':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $friends = Cache::remember('friends_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("
                        SELECT u.* 
                        FROM friend_requests fr
                        JOIN users u ON (u.id = CASE WHEN fr.from_user = :user_id THEN fr.to_user ELSE fr.from_user END)
                        WHERE (fr.from_user = :user_id OR fr.to_user = :user_id) 
                          AND fr.status = 'accepted'
                    ");
                    $stmt->bindValue(':user_id', $user_id);
                    $result = $stmt->execute();
                    
                    $friends = [];
                    while ($friend = $result->fetchArray(SQLITE3_ASSOC)) {
                        $friend['username'] = Encryption::decrypt($friend['username_encrypted']);
                        if ($friend['email_encrypted']) {
                            $friend['email'] = Encryption::decrypt($friend['email_encrypted']);
                        }
                        unset($friend['password'], $friend['username_encrypted'], $friend['email_encrypted'], 
                              $friend['username_hash'], $friend['email_hash'], $friend['username_prefix'],
                              $friend['ip_address_encrypted']);
                        $friends[] = $friend;
                    }
                    
                    return $friends;
                }, 60);
                
                sendJsonResponse(['success' => true, 'friends' => $friends]);
                break;
                
            case 'create_group':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $name = trim($_POST['name'] ?? '');
                $description = trim($_POST['description'] ?? '');
                
                if (strlen($name) < 3 || strlen($name) > 50) {
                    sendJsonResponse(['error' => 'Название группы должно быть от 3 до 50 символов']);
                }
                
                if (!preg_match('/^[a-zA-Z0-9а-яА-ЯёЁ\s\-_]+$/u', $name)) {
                    sendJsonResponse(['error' => 'Название содержит недопустимые символы']);
                }
                
                $nameEncrypted = Encryption::encrypt($name);
                $nameHash = Encryption::encryptForSearch($name);
                $namePrefix = Encryption::encryptForPrefix($name);
                $descEncrypted = $description ? Encryption::encrypt($description) : null;
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        INSERT INTO groups (name_encrypted, name_hash, name_prefix, description_encrypted, creator_id) 
                        VALUES (:name_enc, :name_hash, :name_prefix, :desc_enc, :creator)
                    ");
                    $stmt->bindValue(':name_enc', $nameEncrypted);
                    $stmt->bindValue(':name_hash', $nameHash);
                    $stmt->bindValue(':name_prefix', $namePrefix);
                    $stmt->bindValue(':desc_enc', $descEncrypted);
                    $stmt->bindValue(':creator', $user_id);
                    $stmt->execute();
                    
                    $group_id = $db->lastInsertRowID();
                    
                    $stmt = $dbManager->prepare("INSERT INTO group_members (group_id, user_id, role) VALUES (:group, :user, 'admin')");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    $stmt->execute();
                    
                    $dbManager->commitTransaction();
                    
                    Cache::clear('groups_' . $user_id);
                    
                    sendJsonResponse(['success' => true, 'group_id' => $group_id]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Группа с таким названием уже существует']);
                }
                break;
                
            case 'invite_to_group':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $group_id = (int)$_POST['group_id'];
                $to_user = (int)$_POST['user_id'];
                
                if ($to_user == $user_id) {
                    sendJsonResponse(['error' => 'Нельзя пригласить себя']);
                }
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        SELECT role FROM group_members 
                        WHERE group_id = :group AND user_id = :user
                    ");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    $result = $stmt->execute();
                    $member = $result->fetchArray(SQLITE3_ASSOC);
                    
                    if (!$member || ($member['role'] !== 'admin' && $user_id != $member['user_id'])) {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Недостаточно прав для приглашения']);
                    }
                    
                    $stmt = $dbManager->prepare("
                        SELECT 1 FROM group_members WHERE group_id = :group AND user_id = :user
                    ");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $to_user);
                    if ($stmt->execute()->fetchArray()) {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Пользователь уже в группе']);
                    }
                    
                    $stmt = $dbManager->prepare("
                        INSERT OR IGNORE INTO group_invites (group_id, from_user, to_user) 
                        VALUES (:group, :from, :to)
                    ");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':from', $user_id);
                    $stmt->bindValue(':to', $to_user);
                    $stmt->execute();
                    
                    $dbManager->commitTransaction();
                    
                    Cache::clear('group_invites_' . $to_user);
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка отправки приглашения']);
                }
                break;
                
            case 'get_groups':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $groups = Cache::remember('groups_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("
                        SELECT g.*, 
                               (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count,
                               gm.role as user_role
                        FROM groups g
                        JOIN group_members gm ON g.id = gm.group_id
                        WHERE gm.user_id = :user_id
                    ");
                    $stmt->bindValue(':user_id', $user_id);
                    $result = $stmt->execute();
                    
                    $groups = [];
                    while ($group = $result->fetchArray(SQLITE3_ASSOC)) {
                        $group['name'] = Encryption::decrypt($group['name_encrypted']);
                        if ($group['description_encrypted']) {
                            $group['description'] = Encryption::decrypt($group['description_encrypted']);
                        }
                        unset($group['name_encrypted'], $group['description_encrypted'], $group['name_hash'], $group['name_prefix']);
                        $groups[] = $group;
                    }
                    
                    return $groups;
                }, 60);
                
                sendJsonResponse(['success' => true, 'groups' => $groups]);
                break;
                
            case 'get_group_members':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $group_id = (int)$_POST['group_id'];
                
                $members = Cache::remember('group_members_' . $group_id, function() use ($dbManager, $group_id) {
                    $stmt = $dbManager->prepare("
                        SELECT u.id, u.username_encrypted, u.avatar, u.status, gm.role
                        FROM group_members gm
                        JOIN users u ON u.id = gm.user_id
                        WHERE gm.group_id = :group_id
                    ");
                    $stmt->bindValue(':group_id', $group_id);
                    $result = $stmt->execute();
                    
                    $members = [];
                    while ($member = $result->fetchArray(SQLITE3_ASSOC)) {
                        $member['username'] = Encryption::decrypt($member['username_encrypted']);
                        unset($member['username_encrypted']);
                        $members[] = $member;
                    }
                    
                    return $members;
                }, 30);
                
                sendJsonResponse(['success' => true, 'members' => $members]);
                break;
                
            case 'leave_group':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $group_id = (int)$_POST['group_id'];
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("SELECT creator_id FROM groups WHERE id = :group");
                    $stmt->bindValue(':group', $group_id);
                    $result = $stmt->execute();
                    $group = $result->fetchArray(SQLITE3_ASSOC);
                    
                    if ($group && $group['creator_id'] == $user_id) {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Создатель не может покинуть группу. Удалите группу или передайте права.']);
                    }
                    
                    $stmt = $dbManager->prepare("DELETE FROM group_members WHERE group_id = :group AND user_id = :user");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    $stmt->execute();
                    
                    $dbManager->commitTransaction();
                    
                    Cache::clear('groups_' . $user_id);
                    Cache::clear('group_members_' . $group_id);
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка при выходе из группы']);
                }
                break;
                
            case 'delete_group':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $group_id = (int)$_POST['group_id'];
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("DELETE FROM groups WHERE id = :group AND creator_id = :user");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    $stmt->execute();
                    
                    if ($db->changes() > 0) {
                        $dbManager->commitTransaction();
                        Cache::clear('groups_' . $user_id);
                        Cache::clear('group_members_' . $group_id);
                        sendJsonResponse(['success' => true]);
                    } else {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Нет прав на удаление группы']);
                    }
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка удаления группы']);
                }
                break;
                
            case 'delete_chat':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $chat_with = isset($_POST['chat_with']) ? (int)$_POST['chat_with'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                
                if (!$chat_with && !$group_id) {
                    sendJsonResponse(['error' => 'Не указан чат']);
                }
                
                $dbManager->beginTransaction();
                
                try {
                    if ($chat_with) {
                        $stmt = $dbManager->prepare("
                            DELETE FROM friend_requests 
                            WHERE ((from_user = :user AND to_user = :chat) OR (from_user = :chat AND to_user = :user))
                              AND status = 'accepted'
                        ");
                        $stmt->bindValue(':user', $user_id);
                        $stmt->bindValue(':chat', $chat_with);
                        $stmt->execute();
                        
                        $stmt = $dbManager->prepare("
                            SELECT file_path FROM messages 
                            WHERE (sender_id = :user AND receiver_id = :chat) 
                               OR (sender_id = :chat AND receiver_id = :user)
                        ");
                        $stmt->bindValue(':user', $user_id);
                        $stmt->bindValue(':chat', $chat_with);
                        $result = $stmt->execute();
                        
                        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                            if ($row['file_path']) {
                                $filepath = UPLOAD_DIR . $row['file_path'];
                                if (file_exists($filepath)) {
                                    unlink($filepath);
                                }
                            }
                        }
                        
                        $stmt = $dbManager->prepare("
                            DELETE FROM reactions WHERE message_id IN (
                                SELECT id FROM messages 
                                WHERE (sender_id = :user AND receiver_id = :chat) 
                                   OR (sender_id = :chat AND receiver_id = :user)
                            )
                        ");
                        $stmt->bindValue(':user', $user_id);
                        $stmt->bindValue(':chat', $chat_with);
                        $stmt->execute();
                        
                        $stmt = $dbManager->prepare("
                            DELETE FROM read_receipts WHERE message_id IN (
                                SELECT id FROM messages 
                                WHERE (sender_id = :user AND receiver_id = :chat) 
                                   OR (sender_id = :chat AND receiver_id = :user)
                            )
                        ");
                        $stmt->bindValue(':user', $user_id);
                        $stmt->bindValue(':chat', $chat_with);
                        $stmt->execute();
                        
                        $stmt = $dbManager->prepare("
                            DELETE FROM messages 
                            WHERE (sender_id = :user AND receiver_id = :chat) 
                               OR (sender_id = :chat AND receiver_id = :user)
                        ");
                        $stmt->bindValue(':user', $user_id);
                        $stmt->bindValue(':chat', $chat_with);
                        $stmt->execute();
                        
                    } else if ($group_id) {
                        $stmt = $dbManager->prepare("SELECT creator_id FROM groups WHERE id = :group");
                        $stmt->bindValue(':group', $group_id);
                        $result = $stmt->execute();
                        $group = $result->fetchArray(SQLITE3_ASSOC);
                        
                        if ($group && $group['creator_id'] != $user_id) {
                            $stmt = $dbManager->prepare("DELETE FROM group_members WHERE group_id = :group AND user_id = :user");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->bindValue(':user', $user_id);
                            $stmt->execute();
                        } else {
                            $stmt = $dbManager->prepare("SELECT file_path FROM messages WHERE group_id = :group");
                            $stmt->bindValue(':group', $group_id);
                            $result = $stmt->execute();
                            
                            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                                if ($row['file_path']) {
                                    $filepath = UPLOAD_DIR . $row['file_path'];
                                    if (file_exists($filepath)) {
                                        unlink($filepath);
                                    }
                                }
                            }
                            
                            $stmt = $dbManager->prepare("
                                DELETE FROM reactions WHERE message_id IN (
                                    SELECT id FROM messages WHERE group_id = :group
                                )
                            ");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->execute();
                            
                            $stmt = $dbManager->prepare("
                                DELETE FROM read_receipts WHERE message_id IN (
                                    SELECT id FROM messages WHERE group_id = :group
                                )
                            ");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->execute();
                            
                            $stmt = $dbManager->prepare("DELETE FROM messages WHERE group_id = :group");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->execute();
                            
                            $stmt = $dbManager->prepare("DELETE FROM group_members WHERE group_id = :group");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->execute();
                            
                            $stmt = $dbManager->prepare("DELETE FROM group_invites WHERE group_id = :group");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->execute();
                            
                            $stmt = $dbManager->prepare("DELETE FROM groups WHERE id = :group");
                            $stmt->bindValue(':group', $group_id);
                            $stmt->execute();
                        }
                    }
                    
                    $dbManager->commitTransaction();
                    
                    Cache::clear('friends_' . $user_id);
                    if ($chat_with) {
                        Cache::clear('friends_' . $chat_with);
                    }
                    Cache::clear('messages_' . ($chat_with ?: $group_id));
                    Cache::clear('groups_' . $user_id);
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    error_log("Error in delete_chat: " . $e->getMessage());
                    sendJsonResponse(['error' => 'Ошибка удаления чата']);
                }
                break;
                
            case 'send_message':
                if (!$user_id) throw new Exception('Не авторизован');
                
                if (!Security::checkRateLimit('message', $user_id, RATE_LIMIT_MESSAGES, 60)) {
                    sendJsonResponse(['error' => 'Слишком много сообщений. Подождите минуту.']);
                }
                
                $message = $_POST['message'] ?? '';
                $type = Security::sanitizeInput($_POST['type'] ?? 'text');
                $receiver_id = isset($_POST['receiver_id']) ? (int)$_POST['receiver_id'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                $reply_to = isset($_POST['reply_to']) ? (int)$_POST['reply_to'] : null;
                
                if (!$receiver_id && !$group_id) {
                    sendJsonResponse(['error' => 'Не указан получатель']);
                }
                
                if ($group_id) {
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :group AND user_id = :user");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    if (!$stmt->execute()->fetchArray()) {
                        sendJsonResponse(['error' => 'Вы не состоите в этой группе']);
                    }
                }
                
                if (mb_strlen($message) > 5000) {
                    sendJsonResponse(['error' => 'Сообщение слишком длинное (максимум 5000 символов)']);
                }
                
                $messageEncrypted = Encryption::encrypt($message);
                $messageHash = $message ? Encryption::encryptForSearch($message) : null;
                $messagePrefix = $message ? Encryption::encryptForPrefix($message) : null;
                $encryptedIP = Encryption::encrypt($clientIP);
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        INSERT INTO messages (sender_id, receiver_id, group_id, message_encrypted, message_hash, message_prefix, type, reply_to, ip_address_encrypted) 
                        VALUES (:sender, :receiver, :group, :message_enc, :message_hash, :message_prefix, :type, :reply, :ip)
                    ");
                    $stmt->bindValue(':sender', $user_id);
                    $stmt->bindValue(':receiver', $receiver_id);
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':message_enc', $messageEncrypted);
                    $stmt->bindValue(':message_hash', $messageHash);
                    $stmt->bindValue(':message_prefix', $messagePrefix);
                    $stmt->bindValue(':type', $type);
                    $stmt->bindValue(':reply', $reply_to);
                    $stmt->bindValue(':ip', $encryptedIP);
                    $stmt->execute();
                    
                    $message_id = $db->lastInsertRowID();
                    
                    $dbManager->commitTransaction();
                    
                    $readCount = $dbManager->addReadReceipt($message_id, $user_id);
                    
                    $stmt = $dbManager->prepare("
                        SELECT m.*, u.username_encrypted, u.avatar 
                        FROM messages m
                        JOIN users u ON u.id = m.sender_id
                        WHERE m.id = :id
                    ");
                    $stmt->bindValue(':id', $message_id);
                    $result = $stmt->execute();
                    $newMessage = $result->fetchArray(SQLITE3_ASSOC);
                    
                    if ($newMessage) {
                        $newMessage['message'] = Encryption::decrypt($newMessage['message_encrypted']);
                        $newMessage['username'] = Encryption::decrypt($newMessage['username_encrypted']);
                        $newMessage['read_count'] = $readCount;
                        unset($newMessage['message_encrypted'], $newMessage['message_hash'], 
                              $newMessage['message_prefix'], $newMessage['username_encrypted'],
                              $newMessage['ip_address_encrypted']);
                    }
                    
                    Cache::clear('messages_' . ($receiver_id ?: $group_id));
                    
                    sendJsonResponse(['success' => true, 'message' => $newMessage]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    error_log("Send message error: " . $e->getMessage());
                    sendJsonResponse(['error' => 'Ошибка отправки сообщения']);
                }
                break;
                
            case 'upload_file':
                if (!$user_id) throw new Exception('Не авторизован');
                
                if (!Security::checkRateLimit('file', $user_id, 5, 60)) {
                    sendJsonResponse(['error' => 'Слишком много загрузок. Подождите минуту.']);
                }
                
                if (!isset($_FILES['file'])) {
                    sendJsonResponse(['error' => 'Файл не загружен']);
                }
                
                $file = $_FILES['file'];
                $receiver_id = isset($_POST['receiver_id']) ? (int)$_POST['receiver_id'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                
                if (!$receiver_id && !$group_id) {
                    sendJsonResponse(['error' => 'Не указан получатель']);
                }
                
                $type = strpos($file['type'], 'image/') === 0 ? 'image' : 'file';
                $upload = Security::processUpload($file, $type);
                
                if (isset($upload['error'])) {
                    sendJsonResponse(['error' => $upload['error']]);
                }
                
                if ($group_id) {
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :group AND user_id = :user");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    if (!$stmt->execute()->fetchArray()) {
                        unlink($upload['path']);
                        sendJsonResponse(['error' => 'Вы не состоите в этой группе']);
                    }
                }
                
                $encryptedIP = Encryption::encrypt($clientIP);
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        INSERT INTO messages (sender_id, receiver_id, group_id, type, file_name, file_path, file_size, file_type, ip_address_encrypted) 
                        VALUES (:sender, :receiver, :group, :type, :filename, :path, :size, :filetype, :ip)
                    ");
                    $stmt->bindValue(':sender', $user_id);
                    $stmt->bindValue(':receiver', $receiver_id);
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':type', $type);
                    $stmt->bindValue(':filename', $upload['original_name']);
                    $stmt->bindValue(':path', $upload['filename']);
                    $stmt->bindValue(':size', $upload['size']);
                    $stmt->bindValue(':filetype', $upload['mime_type']);
                    $stmt->bindValue(':ip', $encryptedIP);
                    $stmt->execute();
                    
                    $message_id = $db->lastInsertRowID();
                    
                    $dbManager->commitTransaction();
                    
                    $readCount = $dbManager->addReadReceipt($message_id, $user_id);
                    
                    $stmt = $dbManager->prepare("
                        SELECT m.*, u.username_encrypted, u.avatar 
                        FROM messages m
                        JOIN users u ON u.id = m.sender_id
                        WHERE m.id = :id
                    ");
                    $stmt->bindValue(':id', $message_id);
                    $result = $stmt->execute();
                    $newMessage = $result->fetchArray(SQLITE3_ASSOC);
                    
                    $newMessage['username'] = Encryption::decrypt($newMessage['username_encrypted']);
                    $newMessage['read_count'] = $readCount;
                    unset($newMessage['username_encrypted'], $newMessage['ip_address_encrypted']);
                    
                    Cache::clear('messages_' . ($receiver_id ?: $group_id));
                    
                    sendJsonResponse(['success' => true, 'message' => $newMessage, 'file_url' => UPLOAD_DIR . $upload['filename']]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    unlink($upload['path']);
                    error_log("Upload error: " . $e->getMessage());
                    sendJsonResponse(['error' => 'Ошибка сохранения файла']);
                }
                break;
                
            case 'get_messages':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $chat_with = isset($_POST['chat_with']) ? (int)$_POST['chat_with'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                $before_id = isset($_POST['before_id']) ? (int)$_POST['before_id'] : null;
                $limit = 50;
                
                if (!$chat_with && !$group_id) {
                    sendJsonResponse(['error' => 'Не указан чат']);
                }
                
                if ($group_id) {
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :group AND user_id = :user");
                    $stmt->bindValue(':group', $group_id);
                    $stmt->bindValue(':user', $user_id);
                    if (!$stmt->execute()->fetchArray()) {
                        sendJsonResponse(['error' => 'Нет доступа к группе']);
                    }
                    
                    $query = "
                        SELECT m.*, u.username_encrypted, u.avatar
                        FROM messages m
                        JOIN users u ON u.id = m.sender_id
                        WHERE m.group_id = :chat_id
                    ";
                    
                    if ($before_id) {
                        $query .= " AND m.id < :before_id";
                    }
                    
                    $query .= " ORDER BY m.sent_at DESC LIMIT :limit";
                    
                    $stmt = $dbManager->prepare($query);
                    $stmt->bindValue(':chat_id', $group_id);
                    
                } else {
                    $query = "
                        SELECT m.*, u.username_encrypted, u.avatar
                        FROM messages m
                        JOIN users u ON u.id = m.sender_id
                        WHERE ((m.sender_id = :user_id AND m.receiver_id = :chat_id) 
                            OR (m.sender_id = :chat_id AND m.receiver_id = :user_id))
                    ";
                    
                    if ($before_id) {
                        $query .= " AND m.id < :before_id";
                    }
                    
                    $query .= " ORDER BY m.sent_at DESC LIMIT :limit";
                    
                    $stmt = $dbManager->prepare($query);
                    $stmt->bindValue(':chat_id', $chat_with);
                }
                
                $stmt->bindValue(':user_id', $user_id);
                $stmt->bindValue(':limit', $limit);
                if ($before_id) {
                    $stmt->bindValue(':before_id', $before_id);
                }
                
                $result = $stmt->execute();
                $messages = [];
                $messageIds = [];
                
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $messageIds[] = $row['id'];
                }
                
                $readCounts = $group_id ? $dbManager->getGroupReadCounts($group_id, $messageIds) : [];
                
                $result->reset();
                
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    if ($row['sender_id'] != $user_id) {
                        $dbManager->addReadReceipt($row['id'], $user_id);
                    }
                    
                    $row['read_count'] = $group_id ? ($readCounts[$row['id']] ?? 0) : 1;
                    
                    $row['message'] = Encryption::decrypt($row['message_encrypted'] ?? '');
                    $row['username'] = Encryption::decrypt($row['username_encrypted']);
                    
                    unset($row['message_encrypted'], $row['message_hash'], $row['message_prefix'], 
                          $row['username_encrypted'], $row['ip_address_encrypted']);
                    
                    $messages[] = $row;
                }
                
                $messages = array_reverse($messages);
                
                sendJsonResponse(['success' => true, 'messages' => $messages]);
                break;
                
            case 'add_reaction':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $message_id = (int)$_POST['message_id'];
                $reaction = Security::sanitizeInput($_POST['reaction'] ?? '');
                
                if (mb_strlen($reaction) > 10) {
                    sendJsonResponse(['error' => 'Реакция слишком длинная']);
                }
                
                $stmt = $dbManager->prepare("
                    SELECT 1 FROM messages m
                    LEFT JOIN group_members gm ON m.group_id = gm.group_id
                    WHERE m.id = :msg_id 
                      AND ((m.receiver_id = :user_id OR m.sender_id = :user_id) OR gm.user_id = :user_id)
                ");
                $stmt->bindValue(':msg_id', $message_id);
                $stmt->bindValue(':user_id', $user_id);
                if (!$stmt->execute()->fetchArray()) {
                    sendJsonResponse(['error' => 'Нет доступа к сообщению']);
                }
                
                $dbManager->beginTransaction();
                
                try {
                    if ($reaction) {
                        $stmt = $dbManager->prepare("
                            INSERT OR REPLACE INTO reactions (message_id, user_id, reaction) 
                            VALUES (:msg_id, :user_id, :reaction)
                        ");
                        $stmt->bindValue(':reaction', $reaction);
                    } else {
                        $stmt = $dbManager->prepare("
                            DELETE FROM reactions WHERE message_id = :msg_id AND user_id = :user_id
                        ");
                    }
                    
                    $stmt->bindValue(':msg_id', $message_id);
                    $stmt->bindValue(':user_id', $user_id);
                    $stmt->execute();
                    
                    $dbManager->commitTransaction();
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    sendJsonResponse(['error' => 'Ошибка добавления реакции']);
                }
                break;
                
            case 'get_reactions':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $message_id = (int)$_POST['message_id'];
                
                $stmt = $dbManager->prepare("
                    SELECT r.*, u.username_encrypted
                    FROM reactions r
                    JOIN users u ON u.id = r.user_id
                    WHERE r.message_id = :msg_id
                ");
                $stmt->bindValue(':msg_id', $message_id);
                $result = $stmt->execute();
                
                $reactions = [];
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $row['username'] = Encryption::decrypt($row['username_encrypted']);
                    unset($row['username_encrypted']);
                    $reactions[] = $row;
                }
                
                sendJsonResponse(['success' => true, 'reactions' => $reactions]);
                break;
                
            case 'delete_message':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $message_id = (int)$_POST['message_id'];
                $for_everyone = isset($_POST['for_everyone']) && $_POST['for_everyone'] === 'true';
                
                $dbManager->beginTransaction();
                
                try {
                    $stmt = $dbManager->prepare("
                        SELECT m.*, g.creator_id as group_creator, m.receiver_id, m.group_id, m.file_path
                        FROM messages m
                        LEFT JOIN groups g ON m.group_id = g.id
                        WHERE m.id = :msg_id
                    ");
                    $stmt->bindValue(':msg_id', $message_id);
                    $result = $stmt->execute();
                    $msg = $result->fetchArray(SQLITE3_ASSOC);
                    
                    if (!$msg) {
                        $dbManager->rollbackTransaction();
                        sendJsonResponse(['error' => 'Сообщение не найдено']);
                    }
                    
                    $canDeleteForEveryone = ($msg['sender_id'] == $user_id) || 
                                           ($msg['group_id'] && $msg['group_creator'] == $user_id);
                    
                    if ($for_everyone && $canDeleteForEveryone) {
                        if ($msg['file_path']) {
                            $filepath = UPLOAD_DIR . $msg['file_path'];
                            if (file_exists($filepath)) {
                                unlink($filepath);
                            }
                        }
                        
                        $stmt = $dbManager->prepare("DELETE FROM reactions WHERE message_id = :msg_id");
                        $stmt->bindValue(':msg_id', $message_id);
                        $stmt->execute();
                        
                        $stmt = $dbManager->prepare("DELETE FROM read_receipts WHERE message_id = :msg_id");
                        $stmt->bindValue(':msg_id', $message_id);
                        $stmt->execute();
                        
                        $stmt = $dbManager->prepare("DELETE FROM messages WHERE id = :msg_id");
                        $stmt->bindValue(':msg_id', $message_id);
                        $stmt->execute();
                        
                    } else {
                        if (!$msg['group_id']) {
                            if ($msg['sender_id'] == $user_id) {
                                if ($msg['file_path']) {
                                    $filepath = UPLOAD_DIR . $msg['file_path'];
                                    if (file_exists($filepath)) {
                                        unlink($filepath);
                                    }
                                }
                                
                                $stmt = $dbManager->prepare("DELETE FROM reactions WHERE message_id = :msg_id");
                                $stmt->bindValue(':msg_id', $message_id);
                                $stmt->execute();
                                
                                $stmt = $dbManager->prepare("DELETE FROM read_receipts WHERE message_id = :msg_id");
                                $stmt->bindValue(':msg_id', $message_id);
                                $stmt->execute();
                                
                                $stmt = $dbManager->prepare("DELETE FROM messages WHERE id = :msg_id");
                                $stmt->bindValue(':msg_id', $message_id);
                                $stmt->execute();
                            }
                        }
                    }
                    
                    $dbManager->commitTransaction();
                    
                    Cache::clear('messages_' . ($msg['receiver_id'] ?: $msg['group_id']));
                    
                    sendJsonResponse(['success' => true]);
                    
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    error_log("Error in delete_message: " . $e->getMessage());
                    sendJsonResponse(['error' => 'Ошибка удаления сообщения']);
                }
                break;
                
            case 'edit_message':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $message_id = (int)$_POST['message_id'];
                $new_text = $_POST['message'] ?? '';
                
                if (mb_strlen($new_text) > 5000) {
                    sendJsonResponse(['error' => 'Сообщение слишком длинное']);
                }
                
                $stmt = $dbManager->prepare("
                    SELECT receiver_id, group_id FROM messages
                    WHERE id = :msg_id AND sender_id = :user_id 
                      AND datetime(sent_at) > datetime('now', '-5 minutes')
                ");
                $stmt->bindValue(':msg_id', $message_id);
                $stmt->bindValue(':user_id', $user_id);
                $result = $stmt->execute();
                $msg = $result->fetchArray(SQLITE3_ASSOC);
                
                if ($msg) {
                    $encryptedText = Encryption::encrypt($new_text);
                    $messageHash = Encryption::encryptForSearch($new_text);
                    $messagePrefix = Encryption::encryptForPrefix($new_text);
                    
                    $stmt = $dbManager->prepare("
                        UPDATE messages SET message_encrypted = :message, message_hash = :hash, message_prefix = :prefix, is_edited = 1 
                        WHERE id = :msg_id
                    ");
                    $stmt->bindValue(':msg_id', $message_id);
                    $stmt->bindValue(':message', $encryptedText);
                    $stmt->bindValue(':hash', $messageHash);
                    $stmt->bindValue(':prefix', $messagePrefix);
                    $stmt->execute();
                    
                    Cache::clear('messages_' . ($msg['receiver_id'] ?: $msg['group_id']));
                    
                    sendJsonResponse(['success' => true]);
                } else {
                    sendJsonResponse(['error' => 'Не удалось отредактировать сообщение (прошло более 5 минут или нет прав)']);
                }
                break;
                
            case 'change_theme':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $theme = $_POST['theme'] === 'dark' ? 'dark' : 'light';
                
                $stmt = $dbManager->prepare("UPDATE users SET theme = :theme WHERE id = :id");
                $stmt->bindValue(':theme', $theme);
                $stmt->bindValue(':id', $user_id);
                $stmt->execute();
                
                $_SESSION['theme'] = $theme;
                
                sendJsonResponse(['success' => true]);
                break;
                
            case 'get_online_status':
                if (!$user_id) throw new Exception('Не авторизован');
                
                $user_ids = isset($_POST['user_ids']) ? json_decode($_POST['user_ids'], true) : [];
                
                if (empty($user_ids)) {
                    sendJsonResponse(['success' => true, 'statuses' => []]);
                }
                
                $user_ids = array_filter($user_ids, 'is_numeric');
                $user_ids = array_map('intval', $user_ids);
                
                if (empty($user_ids)) {
                    sendJsonResponse(['success' => true, 'statuses' => []]);
                }
                
                $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
                $stmt = $dbManager->prepare("
                    SELECT id, status, last_seen FROM users WHERE id IN ($placeholders)
                ");
                
                foreach ($user_ids as $i => $id) {
                    $stmt->bindValue($i + 1, $id);
                }
                
                $result = $stmt->execute();
                $statuses = [];
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    $statuses[$row['id']] = [
                        'status' => $row['status'],
                        'last_seen' => $row['last_seen']
                    ];
                }
                
                sendJsonResponse(['success' => true, 'statuses' => $statuses]);
                break;
                
            case 'logout':
                if ($user_id) {
                    if (isset($_SESSION['session_token'])) {
                        $stmt = $dbManager->prepare("DELETE FROM user_sessions WHERE session_token = :token");
                        $stmt->bindValue(':token', $_SESSION['session_token']);
                        $stmt->execute();
                    }
                    
                    $stmt = $dbManager->prepare("UPDATE users SET status = 'offline', last_seen = CURRENT_TIMESTAMP WHERE id = :id");
                    $stmt->bindValue(':id', $user_id);
                    $stmt->execute();
                }
                
                $_SESSION = array();
                session_destroy();
                
                sendJsonResponse(['success' => true]);
                break;
                
            default:
                sendJsonResponse(['error' => 'Неизвестное действие']);
        }
    } catch (Exception $e) {
        error_log("Error in action $action: " . $e->getMessage() . "\n" . $e->getTraceAsString());
        sendJsonResponse(['error' => 'Произошла внутренняя ошибка'], 500);
    }
}

if (isset($_SESSION['user_id'])) {
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
        session_destroy();
        showLoginPage();
        exit;
    }
    
    if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $clientIP) {
        error_log("IP changed for user {$_SESSION['user_id']}: {$_SESSION['ip_address']} -> $clientIP");
    }
    
    if (isset($_SESSION['session_token'])) {
        $stmt = $dbManager->prepare("
            SELECT 1 FROM user_sessions 
            WHERE session_token = :token AND expires_at > CURRENT_TIMESTAMP
        ");
        $stmt->bindValue(':token', $_SESSION['session_token']);
        if (!$stmt->execute()->fetchArray()) {
            session_destroy();
            showLoginPage();
            exit;
        }
    } else {
        session_destroy();
        showLoginPage();
        exit;
    }
}

if (!isset($_SESSION['user_id'])) {
    showLoginPage();
    exit;
}

$user_id = $_SESSION['user_id'];
$stmt = $dbManager->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindValue(':id', $user_id);
$result = $stmt->execute();
$current_user = $result->fetchArray(SQLITE3_ASSOC);

if (!$current_user) {
    session_destroy();
    showLoginPage();
    exit;
}

$current_user['username'] = Encryption::decrypt($current_user['username_encrypted']);
if ($current_user['email_encrypted']) {
    $current_user['email'] = Encryption::decrypt($current_user['email_encrypted']);
}
unset($current_user['username_encrypted'], $current_user['email_encrypted'], 
      $current_user['username_hash'], $current_user['email_hash'], $current_user['username_prefix'],
      $current_user['ip_address_encrypted']);

$stmt = $dbManager->prepare("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = :id");
$stmt->bindValue(':id', $user_id);
$stmt->execute();

$theme = $current_user['theme'] ?? 'light';
if (isset($_SESSION['theme'])) {
    $theme = $_SESSION['theme'];
}

function showLoginPage() {
    $csrf_token = Security::generateCSRFToken();
    $turnstile_site_key = TURNSTILE_SITE_KEY;
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes">
    <meta name="theme-color" content="#0b1120">
    <title>liveto.chat - Безопасный мессенджер</title>
    <link rel="icon" type="image/png" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='45' fill='%23535bf6'/%3E%3Cpath fill='%23fff' d='M30 30 L70 30 L70 50 L55 65 L40 50 L30 50 Z'/%3E%3C/svg%3E">
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #0b1120 0%, #1a1f35 100%);
            min-height: 100vh;
            min-height: -webkit-fill-available;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 16px;
        }
        
        .auth-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 32px;
            padding: 32px 24px;
            width: 100%;
            max-width: 440px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.1);
            animation: slideUp 0.5s ease;
        }
        
        @media (max-width: 480px) {
            .auth-container {
                padding: 24px 20px;
                border-radius: 28px;
            }
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .auth-header {
            text-align: center;
            margin-bottom: 28px;
        }
        
        .auth-header h1 {
            font-size: clamp(2rem, 8vw, 2.5rem);
            background: linear-gradient(135deg, #60a5fa 0%, #a78bfa 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .auth-header p {
            color: #94a3b8;
            font-size: clamp(0.9rem, 4vw, 1rem);
        }
        
        .tab-container {
            display: flex;
            gap: 8px;
            margin-bottom: 28px;
            background: rgba(255, 255, 255, 0.03);
            padding: 6px;
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        
        .tab {
            flex: 1;
            padding: 14px 8px;
            text-align: center;
            border: none;
            background: transparent;
            border-radius: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            color: #94a3b8;
            font-size: 0.95rem;
            touch-action: manipulation;
        }
        
        .tab.active {
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            color: white;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .auth-form {
            display: none;
        }
        
        .auth-form.active {
            display: block;
            animation: fadeIn 0.3s ease;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            color: #e2e8f0;
            font-weight: 500;
            font-size: 0.95rem;
        }
        
        .form-group input {
            width: 100%;
            padding: 16px 18px;
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: rgba(255, 255, 255, 0.05);
            color: white;
            -webkit-appearance: none;
            appearance: none;
        }
        
        .form-group input::placeholder {
            color: #64748b;
        }
        
        .form-group input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.2);
            background: rgba(255, 255, 255, 0.1);
        }
        
        .cf-turnstile {
            margin-bottom: 20px;
            display: flex;
            justify-content: center;
            min-height: 65px;
        }
        
        .btn {
            width: 100%;
            padding: 18px;
            border: none;
            border-radius: 24px;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            color: white;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 8px;
            touch-action: manipulation;
        }
        
        .btn:active {
            transform: scale(0.98);
        }
        
        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }
        
        .error-message {
            color: #ef4444;
            font-size: 0.9rem;
            margin-top: 12px;
            text-align: center;
            background: rgba(239, 68, 68, 0.1);
            padding: 12px;
            border-radius: 16px;
            border: 1px solid rgba(239, 68, 68, 0.2);
        }
        
        .error-message:empty {
            display: none;
        }
        
        .password-hint {
            font-size: 0.85rem;
            color: #64748b;
            margin-top: 6px;
            padding-left: 4px;
        }
        
        .test-mode-badge {
            background: rgba(245, 158, 11, 0.2);
            color: #f59e0b;
            padding: 10px 14px;
            border-radius: 24px;
            font-size: 0.85rem;
            margin-bottom: 20px;
            text-align: center;
            border: 1px solid rgba(245, 158, 11, 0.3);
        }
        
        .security-badge {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            margin-top: 24px;
            color: #64748b;
            font-size: 0.85rem;
            flex-wrap: wrap;
        }
        
        .security-badge svg {
            width: 16px;
            height: 16px;
            fill: none;
            stroke: #10b981;
        }
    </style>
</head>
<body>
    <div class="auth-container">
        <div class="auth-header">
            <h1>🔒 liveto.chat</h1>
            <p>Безопасное и приватное общение</p>
        </div>
        
        <?php if (TURNSTILE_SECRET_KEY === '1x0000000000000000000000000000000AA'): ?>
        <div class="test-mode-badge">
            ⚠️ Режим разработки: капча отключена
        </div>
        <?php endif; ?>
        
        <div class="tab-container">
            <button class="tab active" onclick="switchTab('login')">Вход</button>
            <button class="tab" onclick="switchTab('register')">Регистрация</button>
        </div>
        
        <form id="loginForm" class="auth-form active" onsubmit="handleLogin(event)">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            
            <div class="form-group">
                <label>Имя пользователя или Email</label>
                <input type="text" id="loginUsername" placeholder="username@example.com" required autocomplete="username">
            </div>
            <div class="form-group">
                <label>Пароль</label>
                <input type="password" id="loginPassword" placeholder="••••••••" required autocomplete="current-password">
            </div>
            
            <div class="cf-turnstile" data-sitekey="<?php echo $turnstile_site_key; ?>" data-callback="onTurnstileSuccess"></div>
            
            <button type="submit" class="btn" id="loginBtn" disabled>Войти</button>
            <div id="loginError" class="error-message"></div>
        </form>
        
        <form id="registerForm" class="auth-form" onsubmit="handleRegister(event)">
            <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
            
            <div class="form-group">
                <label>Имя пользователя</label>
                <input type="text" id="regUsername" placeholder="john_doe" required autocomplete="username">
                <div class="password-hint">Только буквы, цифры и _, от 3 до 30 символов</div>
            </div>
            <div class="form-group">
                <label>Email (необязательно)</label>
                <input type="email" id="regEmail" placeholder="john@example.com" autocomplete="email">
            </div>
            <div class="form-group">
                <label>Пароль</label>
                <input type="password" id="regPassword" placeholder="••••••••" required autocomplete="new-password">
                <div class="password-hint">Минимум 8 символов: заглавные, строчные, цифры</div>
            </div>
            <div class="form-group">
                <label>Подтвердите пароль</label>
                <input type="password" id="regConfirmPassword" placeholder="••••••••" required autocomplete="new-password">
            </div>
            
            <div class="cf-turnstile" data-sitekey="<?php echo $turnstile_site_key; ?>" data-callback="onTurnstileSuccess"></div>
            
            <button type="submit" class="btn" id="registerBtn" disabled>Создать аккаунт</button>
            <div id="registerError" class="error-message"></div>
        </form>
        
        <div class="security-badge">
            <svg viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
            </svg>
            <span>AES-256-GCM шифрование</span>
        </div>
    </div>
    
    <script>
        const csrfToken = '<?php echo $csrf_token; ?>';
        let turnstileToken = '';
        
        function onTurnstileSuccess(token) {
            turnstileToken = token;
            document.getElementById('loginBtn').disabled = false;
            document.getElementById('registerBtn').disabled = false;
        }
        
        function switchTab(tab) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
            
            if (tab === 'login') {
                document.querySelectorAll('.tab')[0].classList.add('active');
                document.getElementById('loginForm').classList.add('active');
            } else {
                document.querySelectorAll('.tab')[1].classList.add('active');
                document.getElementById('registerForm').classList.add('active');
            }
        }
        
        async function handleLogin(e) {
            e.preventDefault();
            
            if (!turnstileToken) {
                document.getElementById('loginError').textContent = 'Пожалуйста, подтвердите, что вы не робот';
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'login');
            formData.append('username', document.getElementById('loginUsername').value.trim());
            formData.append('password', document.getElementById('loginPassword').value);
            formData.append('csrf_token', csrfToken);
            formData.append('cf-turnstile-response', turnstileToken);
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (data.success) {
                    window.location.reload();
                } else {
                    document.getElementById('loginError').textContent = data.error || 'Ошибка входа';
                    turnstileToken = '';
                    document.getElementById('loginBtn').disabled = true;
                    if (window.turnstile) {
                        turnstile.reset();
                    }
                }
            } catch (error) {
                document.getElementById('loginError').textContent = 'Ошибка соединения';
            }
        }
        
        async function handleRegister(e) {
            e.preventDefault();
            
            if (!turnstileToken) {
                document.getElementById('registerError').textContent = 'Пожалуйста, подтвердите, что вы не робот';
                return;
            }
            
            const username = document.getElementById('regUsername').value.trim();
            const email = document.getElementById('regEmail').value.trim();
            const password = document.getElementById('regPassword').value;
            const confirm = document.getElementById('regConfirmPassword').value;
            
            if (username.length < 3 || username.length > 30) {
                document.getElementById('registerError').textContent = 'Имя пользователя должно быть от 3 до 30 символов';
                return;
            }
            
            if (!/^[a-zA-Z0-9_]+$/.test(username)) {
                document.getElementById('registerError').textContent = 'Имя пользователя может содержать только буквы, цифры и _';
                return;
            }
            
            if (password.length < 8) {
                document.getElementById('registerError').textContent = 'Пароль должен быть не менее 8 символов';
                return;
            }
            
            if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
                document.getElementById('registerError').textContent = 'Пароль должен содержать заглавные, строчные буквы и цифры';
                return;
            }
            
            if (password !== confirm) {
                document.getElementById('registerError').textContent = 'Пароли не совпадают';
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'register');
            formData.append('username', username);
            formData.append('email', email || '');
            formData.append('password', password);
            formData.append('csrf_token', csrfToken);
            formData.append('cf-turnstile-response', turnstileToken);
            
            try {
                const response = await fetch('', {
                    method: 'POST',
                    body: formData
                });
                const data = await response.json();
                
                if (data.success) {
                    alert('Регистрация успешна! Теперь вы можете войти.');
                    switchTab('login');
                    document.getElementById('loginUsername').value = username;
                    turnstileToken = '';
                    document.getElementById('registerBtn').disabled = true;
                    if (window.turnstile) {
                        turnstile.reset();
                    }
                } else {
                    document.getElementById('registerError').textContent = data.error || 'Ошибка регистрации';
                }
            } catch (error) {
                document.getElementById('registerError').textContent = 'Ошибка соединения';
            }
        }
        
        document.querySelectorAll('input').forEach(input => {
            input.addEventListener('touchstart', () => {
                input.style.fontSize = '16px';
            });
        });
    </script>
</body>
</html>
<?php
    exit;
}
?>

<!DOCTYPE html>
<html lang="ru" data-theme="<?php echo $theme; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=yes, viewport-fit=cover">
    <meta name="theme-color" content="#0f172a">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <title>liveto.chat - <?php echo htmlspecialchars($current_user['username']); ?></title>
    <link rel="icon" type="image/png" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ccircle cx='50' cy='50' r='45' fill='%23535bf6'/%3E%3Cpath fill='%23fff' d='M30 30 L70 30 L70 50 L55 65 L40 50 L30 50 Z'/%3E%3C/svg%3E">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            -webkit-tap-highlight-color: transparent;
        }
        
        :root {
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --bg-tertiary: #f1f5f9;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-tertiary: #64748b;
            --border-color: #e2e8f0;
            --hover-bg: #f1f5f9;
            --active-bg: #e2e8f0;
            --shadow: 0 10px 40px -15px rgba(0,0,0,0.1);
            --message-own: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            --message-other: #f1f5f9;
            --primary: #3b82f6;
            --primary-dark: #2563eb;
            --success: #10b981;
            --danger: #ef4444;
            --warning: #f59e0b;
            --input-bg: #ffffff;
            --sidebar-width: 320px;
            --header-height: 70px;
        }
        
        [data-theme="dark"] {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-tertiary: #334155;
            --text-primary: #f8fafc;
            --text-secondary: #cbd5e1;
            --text-tertiary: #94a3b8;
            --border-color: #334155;
            --hover-bg: #334155;
            --active-bg: #475569;
            --shadow: 0 10px 40px -15px rgba(0,0,0,0.5);
            --message-other: #334155;
            --input-bg: #1e293b;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #0b1120 0%, #1a1f35 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 0;
        }
        
        .app-container {
            width: 100%;
            height: 100vh;
            background: var(--bg-primary);
            display: flex;
            overflow: hidden;
            animation: slideIn 0.5s ease;
            color: var(--text-primary);
            position: relative;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: scale(0.95);
            }
            to {
                opacity: 1;
                transform: scale(1);
            }
        }
        
        .sidebar {
            width: var(--sidebar-width);
            background: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            transition: transform 0.3s ease;
            position: relative;
            z-index: 10;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                transform: translateX(-100%);
                width: 85%;
                max-width: 320px;
                box-shadow: 2px 0 20px rgba(0,0,0,0.3);
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .app-container.show-sidebar .sidebar {
                transform: translateX(0);
            }
        }
        
        .sidebar-header {
            padding: 20px 16px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .user-profile {
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .avatar {
            width: 48px;
            height: 48px;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.2rem;
            position: relative;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
            flex-shrink: 0;
        }
        
        .avatar.online::after {
            content: '';
            position: absolute;
            bottom: 2px;
            right: 2px;
            width: 12px;
            height: 12px;
            background: var(--success);
            border: 2px solid var(--bg-secondary);
            border-radius: 50%;
        }
        
        .user-info {
            flex: 1;
            min-width: 0;
        }
        
        .user-info h4 {
            color: var(--text-primary);
            font-size: 1.1rem;
            margin-bottom: 4px;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .user-info p {
            color: var(--text-tertiary);
            font-size: 0.85rem;
        }
        
        .search-bar {
            padding: 16px;
            position: relative;
        }
        
        .search-bar input {
            width: 100%;
            padding: 14px 18px;
            border: 2px solid var(--border-color);
            border-radius: 30px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
            -webkit-appearance: none;
        }
        
        .search-bar input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.2);
        }
        
        .search-results {
            position: absolute;
            top: 80px;
            left: 16px;
            right: 16px;
            background: var(--bg-primary);
            border-radius: 20px;
            box-shadow: var(--shadow);
            z-index: 100;
            display: none;
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid var(--border-color);
        }
        
        .search-result-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 12px 16px;
            cursor: pointer;
            transition: background 0.3s ease;
            border-bottom: 1px solid var(--border-color);
        }
        
        .search-result-item:last-child {
            border-bottom: none;
        }
        
        .search-result-avatar {
            width: 40px;
            height: 40px;
            border-radius: 12px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            flex-shrink: 0;
        }
        
        .tabs {
            display: flex;
            padding: 0 16px;
            gap: 6px;
            margin-bottom: 12px;
        }
        
        .tab-btn {
            flex: 1;
            padding: 10px 6px;
            border: none;
            background: transparent;
            border-radius: 12px;
            font-weight: 600;
            color: var(--text-tertiary);
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 0.9rem;
            touch-action: manipulation;
        }
        
        .tab-btn.active {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            color: white;
        }
        
        .chat-list {
            flex: 1;
            overflow-y: auto;
            padding: 0 12px;
            -webkit-overflow-scrolling: touch;
        }
        
        .chat-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 14px 12px;
            border-radius: 18px;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 4px;
            background: var(--bg-tertiary);
            border: 1px solid transparent;
            touch-action: manipulation;
        }
        
        .chat-item:active {
            background: var(--active-bg);
            transform: scale(0.98);
        }
        
        .chat-item.active {
            background: linear-gradient(135deg, rgba(59, 130, 246, 0.1), rgba(139, 92, 246, 0.1));
            border-color: var(--primary);
        }
        
        .chat-avatar {
            width: 50px;
            height: 50px;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.1rem;
            flex-shrink: 0;
        }
        
        .chat-info {
            flex: 1;
            min-width: 0;
        }
        
        .chat-name {
            font-weight: 600;
            color: var(--text-primary);
            margin-bottom: 4px;
            font-size: 1rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .chat-last-message {
            font-size: 0.85rem;
            color: var(--text-tertiary);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .chat-actions {
            display: flex;
            gap: 6px;
            opacity: 0;
            transition: opacity 0.3s ease;
        }
        
        .chat-item:hover .chat-actions {
            opacity: 1;
        }
        
        @media (max-width: 768px) {
            .chat-actions {
                opacity: 1;
            }
        }
        
        .chat-action-btn {
            width: 36px;
            height: 36px;
            border: none;
            border-radius: 10px;
            background: var(--bg-primary);
            color: var(--text-primary);
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: all 0.3s ease;
            border: 1px solid var(--border-color);
            touch-action: manipulation;
        }
        
        .chat-action-btn:active {
            background: var(--danger);
            color: white;
            transform: scale(0.95);
        }
        
        .main {
            flex: 1;
            display: flex;
            flex-direction: column;
            background: var(--bg-primary);
            position: relative;
        }
        
        .chat-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: var(--bg-secondary);
            height: var(--header-height);
        }
        
        .menu-toggle {
            display: none;
            width: 40px;
            height: 40px;
            border: none;
            border-radius: 12px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            margin-right: 12px;
            touch-action: manipulation;
        }
        
        @media (max-width: 768px) {
            .menu-toggle {
                display: flex;
                align-items: center;
                justify-content: center;
            }
        }
        
        .chat-header-info {
            display: flex;
            align-items: center;
            gap: 12px;
            flex: 1;
            min-width: 0;
        }
        
        .chat-header-avatar {
            width: 48px;
            height: 48px;
            border-radius: 16px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 1.2rem;
            flex-shrink: 0;
        }
        
        .chat-header-text {
            flex: 1;
            min-width: 0;
        }
        
        .chat-header-text h3 {
            color: var(--text-primary);
            margin-bottom: 4px;
            font-size: 1.1rem;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .chat-header-text p {
            color: var(--success);
            font-size: 0.85rem;
        }
        
        .chat-header-actions {
            display: flex;
            gap: 8px;
        }
        
        .action-btn {
            width: 44px;
            height: 44px;
            border: none;
            border-radius: 14px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            border: 1px solid var(--border-color);
            touch-action: manipulation;
        }
        
        .action-btn:active {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            color: white;
            transform: scale(0.95);
        }
        
        .messages-container {
            flex: 1;
            overflow-y: auto;
            padding: 20px 16px;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background: var(--bg-primary);
            -webkit-overflow-scrolling: touch;
        }
        
        .message-wrapper {
            display: flex;
            gap: 10px;
            max-width: 85%;
            animation: messageIn 0.3s ease;
            position: relative;
        }
        
        @media (min-width: 768px) {
            .message-wrapper {
                max-width: 70%;
            }
        }
        
        .message-wrapper.own {
            align-self: flex-end;
            flex-direction: row-reverse;
        }
        
        .message-avatar {
            width: 36px;
            height: 36px;
            border-radius: 12px;
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.95rem;
            flex-shrink: 0;
        }
        
        .message-content {
            background: var(--message-other);
            padding: 12px 16px;
            border-radius: 18px;
            border-top-left-radius: 4px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            position: relative;
            color: var(--text-primary);
            word-break: break-word;
        }
        
        .message-wrapper.own .message-content {
            background: var(--message-own);
            color: white;
            border-top-left-radius: 18px;
            border-top-right-radius: 4px;
        }
        
        .message-sender {
            font-weight: 600;
            margin-bottom: 4px;
            color: var(--text-primary);
            font-size: 0.9rem;
        }
        
        .message-wrapper.own .message-sender {
            color: rgba(255,255,255,0.9);
        }
        
        .message-text {
            line-height: 1.5;
            word-break: break-word;
            font-size: 0.95rem;
        }
        
        .message-time {
            font-size: 0.65rem;
            color: var(--text-tertiary);
            margin-top: 4px;
            text-align: right;
        }
        
        .message-wrapper.own .message-time {
            color: rgba(255,255,255,0.7);
        }
        
        .message-image {
            max-width: 100%;
            max-height: 250px;
            border-radius: 12px;
            cursor: pointer;
            transition: transform 0.3s ease;
        }
        
        .message-image:active {
            transform: scale(0.98);
        }
        
        .message-file {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 10px;
            background: rgba(0,0,0,0.05);
            border-radius: 12px;
            cursor: pointer;
            transition: background 0.3s ease;
        }
        
        .message-wrapper.own .message-file {
            background: rgba(255,255,255,0.1);
        }
        
        .message-file:active {
            background: rgba(0,0,0,0.1);
        }
        
        .message-wrapper.own .message-file:active {
            background: rgba(255,255,255,0.2);
        }
        
        .message-form {
            padding: 16px;
            border-top: 1px solid var(--border-color);
            display: flex;
            gap: 10px;
            align-items: flex-end;
            background: var(--bg-secondary);
            position: sticky;
            bottom: 0;
        }
        
        .message-input-wrapper {
            flex: 1;
            position: relative;
        }
        
        .message-input {
            width: 100%;
            padding: 14px 18px;
            border: 2px solid var(--border-color);
            border-radius: 28px;
            font-size: 16px;
            resize: none;
            max-height: 100px;
            font-family: inherit;
            transition: all 0.3s ease;
            background: var(--input-bg);
            color: var(--text-primary);
            -webkit-appearance: none;
        }
        
        .message-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 4px rgba(59, 130, 246, 0.2);
        }
        
        .message-actions {
            display: flex;
            gap: 6px;
        }
        
        .attach-btn, .emoji-btn, .send-btn {
            width: 48px;
            height: 48px;
            border: none;
            border-radius: 50%;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            touch-action: manipulation;
            font-size: 1.3rem;
        }
        
        .attach-btn, .emoji-btn {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 2px solid var(--border-color);
        }
        
        .send-btn {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            color: white;
            box-shadow: 0 4px 12px rgba(59, 130, 246, 0.3);
        }
        
        .attach-btn:active, .emoji-btn:active {
            background: var(--primary);
            color: white;
            transform: scale(0.95);
        }
        
        .send-btn:active {
            transform: scale(0.95);
        }
        
        .emoji-picker {
            position: fixed;
            bottom: 80px;
            right: 16px;
            left: 16px;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: 24px;
            padding: 16px;
            display: none;
            grid-template-columns: repeat(6, 1fr);
            gap: 8px;
            max-height: 250px;
            overflow-y: auto;
            box-shadow: var(--shadow);
            z-index: 1000;
            -webkit-overflow-scrolling: touch;
        }
        
        @media (min-width: 480px) {
            .emoji-picker {
                left: auto;
                width: 350px;
            }
        }
        
        .emoji-item {
            font-size: 1.8rem;
            padding: 8px;
            cursor: pointer;
            border-radius: 12px;
            text-align: center;
            transition: all 0.3s ease;
            touch-action: manipulation;
        }
        
        .emoji-item:active {
            background: var(--hover-bg);
            transform: scale(1.1);
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.7);
            z-index: 2000;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(5px);
            padding: 16px;
        }
        
        .modal-content {
            background: var(--bg-primary);
            border-radius: 28px;
            padding: 24px 20px;
            max-width: 500px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            animation: modalIn 0.3s ease;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
            -webkit-overflow-scrolling: touch;
        }
        
        @media (max-width: 480px) {
            .modal-content {
                padding: 20px 16px;
            }
        }
        
        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        
        .modal-header h3 {
            color: var(--text-primary);
            font-size: 1.3rem;
        }
        
        .close-btn {
            background: none;
            border: none;
            font-size: 2rem;
            cursor: pointer;
            color: var(--text-tertiary);
            transition: color 0.3s ease;
            line-height: 1;
            padding: 0 8px;
        }
        
        .close-btn:active {
            color: var(--danger);
        }
        
        .modal-footer {
            display: flex;
            gap: 12px;
            justify-content: flex-end;
            margin-top: 24px;
            flex-wrap: wrap;
        }
        
        .modal-btn {
            padding: 14px 24px;
            border: none;
            border-radius: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 1rem;
            touch-action: manipulation;
            flex: 1 1 auto;
        }
        
        @media (max-width: 480px) {
            .modal-btn {
                padding: 16px 20px;
            }
        }
        
        .modal-btn.primary {
            background: linear-gradient(135deg, var(--primary), #8b5cf6);
            color: white;
        }
        
        .modal-btn.secondary {
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
        }
        
        .modal-btn.danger {
            background: var(--danger);
            color: white;
        }
        
        .modal-btn:active {
            transform: scale(0.97);
        }
        
        .friend-request-item, .group-invite-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 14px;
            background: var(--bg-tertiary);
            border-radius: 16px;
            margin-bottom: 12px;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
            gap: 12px;
        }
        
        .member-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px;
            background: var(--bg-tertiary);
            border-radius: 14px;
            margin-bottom: 8px;
            border: 1px solid var(--border-color);
            flex-wrap: wrap;
            gap: 10px;
        }
        
        .member-role {
            font-size: 0.75rem;
            padding: 4px 10px;
            background: var(--primary);
            color: white;
            border-radius: 20px;
        }
        
        .theme-toggle {
            margin: 12px 16px;
        }
        
        .theme-toggle button {
            width: 100%;
            padding: 14px;
            border: 2px solid var(--border-color);
            border-radius: 20px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            cursor: pointer;
            font-size: 1rem;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            transition: all 0.3s ease;
            touch-action: manipulation;
        }
        
        .theme-toggle button:active {
            border-color: var(--primary);
            background: var(--hover-bg);
            transform: scale(0.98);
        }
        
        .badge {
            background: var(--primary);
            color: white;
            border-radius: 20px;
            padding: 2px 8px;
            font-size: 0.7rem;
            margin-left: 6px;
        }
        
        ::-webkit-scrollbar {
            width: 6px;
        }
        
        ::-webkit-scrollbar-track {
            background: var(--bg-tertiary);
        }
        
        ::-webkit-scrollbar-thumb {
            background: var(--primary);
            border-radius: 3px;
        }
        
        .loading {
            text-align: center;
            padding: 30px;
            color: var(--text-tertiary);
        }
        
        .security-badge {
            font-size: 0.8rem;
            color: var(--text-tertiary);
            text-align: center;
            padding: 12px;
            border-top: 1px solid var(--border-color);
        }
        
        .message-reactions {
            display: flex;
            gap: 4px;
            flex-wrap: wrap;
            margin-top: 6px;
        }
        
        .reaction-badge {
            background: rgba(0,0,0,0.1);
            border-radius: 12px;
            padding: 2px 8px;
            font-size: 0.8rem;
            display: inline-flex;
            align-items: center;
            gap: 4px;
            cursor: pointer;
        }
        
        .message-wrapper.own .reaction-badge {
            background: rgba(255,255,255,0.2);
        }
        
        .online-status-dot {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--success);
            margin-left: 4px;
        }
    </style>
</head>
<body>
    <div class="app-container" id="appContainer">
        <div class="sidebar" id="sidebar">
            <div class="sidebar-header">
                <div class="user-profile">
                    <div class="avatar online">
                        <?php echo strtoupper(substr($current_user['username'], 0, 1)); ?>
                    </div>
                    <div class="user-info">
                        <h4><?php echo htmlspecialchars($current_user['username']); ?></h4>
                        <p>В сети</p>
                    </div>
                </div>
            </div>
            
            <div class="search-bar">
                <input type="text" id="searchInput" placeholder="Поиск..." onkeyup="searchUsers(event)" onfocus="this.value=''">
                <div id="searchResults" class="search-results"></div>
            </div>
            
            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab('chats')">Чаты</button>
                <button class="tab-btn" onclick="switchTab('groups')">Группы</button>
                <button class="tab-btn" onclick="switchTab('contacts')">Контакты</button>
            </div>
            
            <div class="chat-list" id="chatList"></div>
            
            <div class="theme-toggle">
                <button onclick="toggleTheme()">
                    <span id="themeIcon"><?php echo $theme === 'dark' ? '☀️' : '🌙'; ?></span>
                    <span id="themeText"><?php echo $theme === 'dark' ? 'Светлая тема' : 'Темная тема'; ?></span>
                </button>
            </div>
            
            <div style="padding: 12px 16px; display: flex; gap: 8px; justify-content: space-around;">
                <button class="action-btn" onclick="showRequestsModal()" style="width: 48px;" title="Запросы">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                        <circle cx="9" cy="7" r="4"></circle>
                    </svg>
                    <span id="requestsBadge" class="badge" style="display: none;">0</span>
                </button>
                <button class="action-btn" onclick="showCreateGroupModal()" style="width: 48px;" title="Создать группу">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="8" r="4"></circle>
                        <path d="M5.5 20v-2a5 5 0 0 1 10 0v2"></path>
                        <line x1="18" y1="8" x2="22" y2="8"></line>
                        <line x1="20" y1="6" x2="20" y2="10"></line>
                    </svg>
                </button>
                <button class="action-btn" onclick="logout()" style="width: 48px;" title="Выйти">
                    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path>
                        <polyline points="16 17 21 12 16 7"></polyline>
                        <line x1="21" y1="12" x2="9" y2="12"></line>
                    </svg>
                </button>
            </div>
            
            <div class="security-badge">
                🔒 AES-256-GCM шифрование
            </div>
        </div>
        
        <div class="main">
            <div class="chat-header" id="chatHeader">
                <button class="menu-toggle" onclick="toggleSidebar()" id="menuToggle">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="3" y1="12" x2="21" y2="12"></line>
                        <line x1="3" y1="6" x2="21" y2="6"></line>
                        <line x1="3" y1="18" x2="21" y2="18"></line>
                    </svg>
                </button>
                <div class="chat-header-info">
                    <div class="chat-header-avatar" id="chatAvatar">👤</div>
                    <div class="chat-header-text">
                        <h3 id="chatTitle">Выберите чат</h3>
                        <p id="chatStatus">Начните общение</p>
                    </div>
                </div>
                <div class="chat-header-actions">
                    <button class="action-btn" onclick="showGroupInfo()" title="Информация" id="groupInfoBtn" style="display: none;">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="10"></circle>
                            <line x1="12" y1="16" x2="12" y2="12"></line>
                            <line x1="12" y1="8" x2="12.01" y2="8"></line>
                        </svg>
                    </button>
                    <button class="action-btn" onclick="showChatActions()" title="Действия" id="chatActionsBtn" style="display: none;">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <circle cx="12" cy="12" r="1"></circle>
                            <circle cx="19" cy="12" r="1"></circle>
                            <circle cx="5" cy="12" r="1"></circle>
                        </svg>
                    </button>
                </div>
            </div>
            
            <div class="messages-container" id="messages"></div>
            
            <div class="emoji-picker" id="emojiPicker"></div>
            
            <div class="message-form">
                <div class="message-actions">
                    <button class="attach-btn" onclick="document.getElementById('fileInput').click()" title="Файл">
                        📎
                    </button>
                    <input type="file" id="fileInput" style="display: none;" onchange="uploadFile()" accept="image/jpeg,image/png,image/gif,image/webp,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document,text/plain">
                    
                    <button class="emoji-btn" onclick="toggleEmojiPicker()" title="Эмодзи">
                        😊
                    </button>
                </div>
                
                <div class="message-input-wrapper">
                    <textarea 
                        id="messageInput"
                        class="message-input"
                        placeholder="Сообщение..."
                        rows="1"
                        onkeydown="handleKeyPress(event)"
                        oninput="autoResize(this)"
                        maxlength="5000"
                    ></textarea>
                </div>
                
                <button class="send-btn" onclick="sendMessage()">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <line x1="22" y1="2" x2="11" y2="13"></line>
                        <polygon points="22 2 15 22 11 13 2 9 22 2"></polygon>
                    </svg>
                </button>
            </div>
        </div>
    </div>

    <div id="requestsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Запросы и приглашения</h3>
                <button class="close-btn" onclick="hideModal('requestsModal')">&times;</button>
            </div>
            <div class="modal-body">
                <h4 style="margin-bottom: 10px;">Запросы в друзья</h4>
                <div id="friendRequestsList" class="loading">Загрузка...</div>
                
                <h4 style="margin: 20px 0 10px;">Приглашения в группы</h4>
                <div id="groupInvitesList" class="loading">Загрузка...</div>
            </div>
        </div>
    </div>

    <div id="createGroupModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Создать группу</h3>
                <button class="close-btn" onclick="hideModal('createGroupModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div class="form-group" style="margin-bottom: 16px;">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-primary);">Название</label>
                    <input type="text" id="groupName" placeholder="Введите название" style="width: 100%; padding: 14px; border: 2px solid var(--border-color); border-radius: 16px; background: var(--input-bg); color: var(--text-primary); font-size: 16px;" maxlength="50">
                </div>
                <div class="form-group">
                    <label style="display: block; margin-bottom: 8px; color: var(--text-primary);">Описание</label>
                    <textarea id="groupDescription" placeholder="Описание группы" style="width: 100%; padding: 14px; border: 2px solid var(--border-color); border-radius: 16px; background: var(--input-bg); color: var(--text-primary);" rows="3" maxlength="500"></textarea>
                </div>
            </div>
            <div class="modal-footer">
                <button class="modal-btn secondary" onclick="hideModal('createGroupModal')">Отмена</button>
                <button class="modal-btn primary" onclick="createGroup()">Создать</button>
            </div>
        </div>
    </div>

    <div id="groupInfoModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="groupInfoName">Информация о группе</h3>
                <button class="close-btn" onclick="hideModal('groupInfoModal')">&times;</button>
            </div>
            <div class="modal-body">
                <div id="groupDescriptionDisplay" style="margin-bottom: 20px; padding: 12px; background: var(--bg-tertiary); border-radius: 14px;"></div>
                
                <h4 style="margin: 20px 0 12px">Участники</h4>
                <div id="groupMembersList"></div>
                
                <h4 style="margin: 20px 0 12px">Пригласить друзей</h4>
                <div id="friendsToInvite"></div>
                
                <div style="margin-top: 20px; display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="modal-btn danger" onclick="leaveGroup()" id="leaveGroupBtn">Покинуть</button>
                    <button class="modal-btn danger" onclick="deleteGroup()" id="deleteGroupBtn">Удалить</button>
                </div>
            </div>
        </div>
    </div>

    <div id="chatActionsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Действия с чатом</h3>
                <button class="close-btn" onclick="hideModal('chatActionsModal')">&times;</button>
            </div>
            <div class="modal-body">
                <button class="modal-btn danger" style="width: 100%; margin-bottom: 10px;" onclick="deleteChat()">
                    Удалить чат
                </button>
                <button class="modal-btn secondary" style="width: 100%;" onclick="hideModal('chatActionsModal')">
                    Отмена
                </button>
            </div>
        </div>
    </div>

    <div id="messageActionsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Действия с сообщением</h3>
                <button class="close-btn" onclick="hideModal('messageActionsModal')">&times;</button>
            </div>
            <div class="modal-body">
                <button class="modal-btn primary" style="width: 100%; margin-bottom: 10px;" onclick="editMessage()">
                    Редактировать
                </button>
                <button class="modal-btn danger" style="width: 100%; margin-bottom: 10px;" onclick="deleteMessage(true)">
                    Удалить для всех
                </button>
                <button class="modal-btn secondary" style="width: 100%;" onclick="hideModal('messageActionsModal')">
                    Отмена
                </button>
            </div>
        </div>
    </div>

    <div id="editMessageModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Редактировать</h3>
                <button class="close-btn" onclick="hideModal('editMessageModal')">&times;</button>
            </div>
            <div class="modal-body">
                <textarea id="editMessageText" style="width: 100%; padding: 14px; border: 2px solid var(--border-color); border-radius: 16px; background: var(--input-bg); color: var(--text-primary);" rows="3" maxlength="5000"></textarea>
            </div>
            <div class="modal-footer">
                <button class="modal-btn secondary" onclick="hideModal('editMessageModal')">Отмена</button>
                <button class="modal-btn primary" onclick="saveEditedMessage()">Сохранить</button>
            </div>
        </div>
    </div>

    <div id="imagePreviewModal" class="modal" onclick="hideModal('imagePreviewModal')">
        <div class="modal-content" style="max-width: 90%; text-align: center; background: transparent; box-shadow: none;" onclick="event.stopPropagation()">
            <img id="previewImage" src="" alt="Preview" style="max-width: 100%; max-height: 80vh; border-radius: 16px;">
        </div>
    </div>

    <div id="reactionsModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Реакции</h3>
                <button class="close-btn" onclick="hideModal('reactionsModal')">&times;</button>
            </div>
            <div class="modal-body" id="reactionsList"></div>
        </div>
    </div>

    <script>
        const currentUser = <?php echo json_encode($current_user); ?>;
        const csrfToken = '<?php echo Security::generateCSRFToken(); ?>';
        const UPLOAD_DIR = '<?php echo UPLOAD_DIR; ?>';
        
        let activeChat = null;
        let activeGroup = null;
        let friends = [];
        let groups = [];
        let messages = [];
        let emojis = ['😊', '😂', '❤️', '👍', '😢', '😡', '🎉', '🔥', '✨', '🥳', '🤔', '😎', '💯', '⭐', '👏', '🙏', '💔', '✅', '❌'];
        let selectedMessageId = null;
        let onlineStatusInterval = null;
        let lastMessageId = 0;
        
        document.addEventListener('DOMContentLoaded', function() {
            loadFriends();
            loadGroups();
            loadEmojiPicker();
            loadRequestsCount();
            setInterval(loadMessages, 3000);
            setInterval(loadRequestsCount, 10000);
            setInterval(updateOnlineStatuses, 30000);
            
            document.addEventListener('click', function(e) {
                const sidebar = document.getElementById('sidebar');
                const menuToggle = document.getElementById('menuToggle');
                if (window.innerWidth <= 768 && sidebar.classList.contains('active') && 
                    !sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
                    toggleSidebar();
                }
            });
            
            const messagesContainer = document.getElementById('messages');
            messagesContainer.addEventListener('scroll', function() {
                if (this.scrollTop === 0 && messages.length > 0 && messages[0].id > 1) {
                    loadMoreMessages();
                }
            });
        });
        
        function autoResize(textarea) {
            textarea.style.height = 'auto';
            textarea.style.height = Math.min(textarea.scrollHeight, 100) + 'px';
        }
        
        function toggleSidebar() {
            document.getElementById('sidebar').classList.toggle('active');
        }
        
        function loadEmojiPicker() {
            const picker = document.getElementById('emojiPicker');
            let html = '';
            emojis.forEach(emoji => {
                html += `<div class="emoji-item" onclick="addEmoji('${emoji}')">${emoji}</div>`;
            });
            picker.innerHTML = html;
        }
        
        function loadRequestsCount() {
            Promise.all([
                fetch('', {
                    method: 'POST',
                    body: new URLSearchParams({
                        action: 'get_friend_requests',
                        csrf_token: csrfToken
                    })
                }).then(r => r.json()),
                fetch('', {
                    method: 'POST',
                    body: new URLSearchParams({
                        action: 'get_group_invites',
                        csrf_token: csrfToken
                    })
                }).then(r => r.json())
            ]).then(([friendData, groupData]) => {
                const count = (friendData.requests?.length || 0) + (groupData.invites?.length || 0);
                const badge = document.getElementById('requestsBadge');
                if (count > 0) {
                    badge.style.display = 'inline';
                    badge.textContent = count;
                } else {
                    badge.style.display = 'none';
                }
            }).catch(error => console.error('Error loading requests:', error));
        }
        
        function toggleTheme() {
            const html = document.documentElement;
            const currentTheme = html.getAttribute('data-theme');
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            
            html.setAttribute('data-theme', newTheme);
            
            document.getElementById('themeIcon').textContent = newTheme === 'dark' ? '☀️' : '🌙';
            document.getElementById('themeText').textContent = newTheme === 'dark' ? 'Светлая тема' : 'Темная тема';
            
            const formData = new FormData();
            formData.append('action', 'change_theme');
            formData.append('theme', newTheme);
            formData.append('csrf_token', csrfToken);
            
            fetch('', { method: 'POST', body: formData })
                .catch(error => console.error('Error saving theme:', error));
        }
        
        function toggleEmojiPicker() {
            const picker = document.getElementById('emojiPicker');
            picker.style.display = picker.style.display === 'grid' ? 'none' : 'grid';
        }
        
        function addEmoji(emoji) {
            const input = document.getElementById('messageInput');
            input.value += emoji;
            input.focus();
            autoResize(input);
            document.getElementById('emojiPicker').style.display = 'none';
        }
        
        function searchUsers(event) {
            if (event.key === 'Escape') {
                document.getElementById('searchResults').style.display = 'none';
                return;
            }
            
            const query = document.getElementById('searchInput').value;
            if (query.length < 2) {
                document.getElementById('searchResults').style.display = 'none';
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'search_users');
            formData.append('query', query);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displaySearchResults(data.users);
                }
            })
            .catch(error => console.error('Search error:', error));
        }
        
        function displaySearchResults(users) {
            const resultsDiv = document.getElementById('searchResults');
            if (users.length === 0) {
                resultsDiv.style.display = 'none';
                return;
            }
            
            let html = '';
            users.forEach(user => {
                const isFriend = friends.some(f => f.id == user.id);
                html += `
                    <div class="search-result-item">
                        <div class="search-result-avatar">${escapeHtml(user.username[0].toUpperCase())}</div>
                        <div style="flex: 1; min-width: 0;">
                            <div style="font-weight: 600; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                ${escapeHtml(user.username)}
                                <span class="online-status-dot" style="background: ${user.status === 'online' ? 'var(--success)' : '#94a3b8'};"></span>
                            </div>
                            <div style="font-size: 0.8rem; color: var(--text-tertiary);">${user.status === 'online' ? 'В сети' : 'Был(а) недавно'}</div>
                        </div>
                        ${!isFriend ? `
                            <button class="modal-btn primary" onclick="sendFriendRequest(${user.id})" style="padding: 8px 12px; font-size: 0.9rem;">➕</button>
                        ` : ''}
                    </div>
                `;
            });
            
            resultsDiv.innerHTML = html;
            resultsDiv.style.display = 'block';
        }
        
        function sendFriendRequest(userId) {
            const formData = new FormData();
            formData.append('action', 'send_friend_request');
            formData.append('user_id', userId);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Запрос отправлен!');
                    document.getElementById('searchResults').style.display = 'none';
                    document.getElementById('searchInput').value = '';
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function showRequestsModal() {
            document.getElementById('requestsModal').style.display = 'flex';
            loadFriendRequests();
            loadGroupInvites();
        }
        
        function loadFriendRequests() {
            const formData = new FormData();
            formData.append('action', 'get_friend_requests');
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayFriendRequests(data.requests);
                }
            })
            .catch(error => console.error('Error loading requests:', error));
        }
        
        function displayFriendRequests(requests) {
            const listDiv = document.getElementById('friendRequestsList');
            
            if (requests.length === 0) {
                listDiv.innerHTML = '<p style="text-align: center; color: var(--text-tertiary); padding: 20px;">Нет запросов</p>';
            } else {
                let html = '';
                requests.forEach(req => {
                    html += `
                        <div class="friend-request-item">
                            <div style="display: flex; align-items: center; gap: 12px; min-width: 0;">
                                <div class="avatar" style="width: 44px; height: 44px;">${escapeHtml(req.username[0].toUpperCase())}</div>
                                <div style="min-width: 0;">
                                    <div style="font-weight: 600; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                        ${escapeHtml(req.username)}
                                    </div>
                                    <div style="font-size: 0.75rem; color: var(--text-tertiary);">Хочет добавить вас</div>
                                </div>
                            </div>
                            <div style="display: flex; gap: 8px;">
                                <button class="modal-btn primary" onclick="respondToFriendRequest(${req.id}, true)" style="padding: 8px 16px;">✓</button>
                                <button class="modal-btn secondary" onclick="respondToFriendRequest(${req.id}, false)" style="padding: 8px 16px;">✗</button>
                            </div>
                        </div>
                    `;
                });
                listDiv.innerHTML = html;
            }
        }
        
        function loadGroupInvites() {
            const formData = new FormData();
            formData.append('action', 'get_group_invites');
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayGroupInvites(data.invites);
                }
            })
            .catch(error => console.error('Error loading invites:', error));
        }
        
        function displayGroupInvites(invites) {
            const listDiv = document.getElementById('groupInvitesList');
            
            if (invites.length === 0) {
                listDiv.innerHTML = '<p style="text-align: center; color: var(--text-tertiary); padding: 20px;">Нет приглашений</p>';
            } else {
                let html = '';
                invites.forEach(invite => {
                    html += `
                        <div class="group-invite-item">
                            <div style="min-width: 0;">
                                <div style="font-weight: 600; color: var(--text-primary);">${escapeHtml(invite.group_name)}</div>
                                <div style="font-size: 0.8rem; color: var(--text-tertiary);">от ${escapeHtml(invite.inviter_name)}</div>
                            </div>
                            <div style="display: flex; gap: 8px;">
                                <button class="modal-btn primary" onclick="respondToGroupInvite(${invite.id}, true)" style="padding: 8px 16px;">✓</button>
                                <button class="modal-btn secondary" onclick="respondToGroupInvite(${invite.id}, false)" style="padding: 8px 16px;">✗</button>
                            </div>
                        </div>
                    `;
                });
                listDiv.innerHTML = html;
            }
        }
        
        function respondToFriendRequest(requestId, accept) {
            const formData = new FormData();
            formData.append('action', 'respond_friend_request');
            formData.append('request_id', requestId);
            formData.append('accept', accept);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadFriends();
                    loadFriendRequests();
                    loadRequestsCount();
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function respondToGroupInvite(inviteId, accept) {
            const formData = new FormData();
            formData.append('action', 'respond_group_invite');
            formData.append('invite_id', inviteId);
            formData.append('accept', accept);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadGroups();
                    loadGroupInvites();
                    loadRequestsCount();
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function loadFriends() {
            const formData = new FormData();
            formData.append('action', 'get_friends');
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    friends = data.friends;
                    updateChatList();
                    
                    if (activeChat && !friends.some(f => f.id == activeChat)) {
                        activeChat = null;
                        updateChatHeader();
                        document.getElementById('messages').innerHTML = '';
                    }
                }
            })
            .catch(error => console.error('Error loading friends:', error));
        }
        
        function loadGroups() {
            const formData = new FormData();
            formData.append('action', 'get_groups');
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    groups = data.groups;
                    updateChatList();
                }
            })
            .catch(error => console.error('Error loading groups:', error));
        }
        
        function updateOnlineStatuses() {
            const userIds = friends.map(f => f.id);
            if (userIds.length === 0) return;
            
            const formData = new FormData();
            formData.append('action', 'get_online_status');
            formData.append('user_ids', JSON.stringify(userIds));
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    friends.forEach(friend => {
                        if (data.statuses[friend.id]) {
                            friend.status = data.statuses[friend.id].status;
                            friend.last_seen = data.statuses[friend.id].last_seen;
                        }
                    });
                    updateChatList();
                }
            })
            .catch(error => console.error('Error updating online statuses:', error));
        }
        
        function updateChatList() {
            const chatList = document.getElementById('chatList');
            let html = '';
            
            friends.forEach(friend => {
                const lastSeen = friend.last_seen ? new Date(friend.last_seen) : null;
                const isOnline = friend.status === 'online';
                const timeAgo = lastSeen ? timeSince(lastSeen) : '';
                
                html += `
                    <div class="chat-item ${activeChat == friend.id ? 'active' : ''}" onclick="openChat(${friend.id})">
                        <div class="chat-avatar" style="position: relative;">
                            ${escapeHtml(friend.username[0].toUpperCase())}
                            ${isOnline ? '<span class="online-status-dot" style="position: absolute; bottom: 2px; right: 2px;"></span>' : ''}
                        </div>
                        <div class="chat-info">
                            <div class="chat-name">${escapeHtml(friend.username)}</div>
                            <div class="chat-last-message">${isOnline ? 'В сети' : (timeAgo ? 'Был ' + timeAgo : 'Офлайн')}</div>
                        </div>
                        <div class="chat-actions">
                            <button class="chat-action-btn" onclick="event.stopPropagation(); deleteChatById(${friend.id}, 'user')" title="Удалить">
                                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="3 6 5 6 21 6"></polyline>
                                    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                </svg>
                            </button>
                        </div>
                    </div>
                `;
            });
            
            groups.forEach(group => {
                const isAdmin = group.user_role === 'admin' || group.creator_id == currentUser.id;
                html += `
                    <div class="chat-item ${activeGroup == group.id ? 'active' : ''}" onclick="openGroup(${group.id})">
                        <div class="chat-avatar">#</div>
                        <div class="chat-info">
                            <div class="chat-name">${escapeHtml(group.name)}</div>
                            <div class="chat-last-message">${group.member_count || 0} участников</div>
                        </div>
                        <div class="chat-actions">
                            ${isAdmin ? `
                                <button class="chat-action-btn" onclick="event.stopPropagation(); deleteGroupById(${group.id})" title="Удалить">
                                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                        <polyline points="3 6 5 6 21 6"></polyline>
                                        <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
                                    </svg>
                                </button>
                            ` : ''}
                        </div>
                    </div>
                `;
            });
            
            if (html === '') {
                html = '<p style="text-align: center; color: var(--text-tertiary); padding: 40px 20px;">Нет чатов<br><small>Найдите друзей через поиск</small></p>';
            }
            
            chatList.innerHTML = html;
        }
        
        function timeSince(date) {
            const seconds = Math.floor((new Date() - date) / 1000);
            
            let interval = seconds / 31536000;
            if (interval > 1) return Math.floor(interval) + ' г. назад';
            
            interval = seconds / 2592000;
            if (interval > 1) return Math.floor(interval) + ' мес. назад';
            
            interval = seconds / 86400;
            if (interval > 1) return Math.floor(interval) + ' д. назад';
            
            interval = seconds / 3600;
            if (interval > 1) return Math.floor(interval) + ' ч. назад';
            
            interval = seconds / 60;
            if (interval > 1) return Math.floor(interval) + ' мин. назад';
            
            return 'только что';
        }
        
        function deleteChatById(id, type) {
            if (!confirm('Удалить чат? Это также удалит пользователя из друзей. Для нового общения нужно будет снова отправить запрос в друзья.')) return;
            
            const formData = new FormData();
            formData.append('action', 'delete_chat');
            formData.append(type === 'user' ? 'chat_with' : 'group_id', id);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (type === 'user') {
                        friends = friends.filter(f => f.id != id);
                    } else {
                        groups = groups.filter(g => g.id != id);
                    }
                    updateChatList();
                    if ((type === 'user' && activeChat == id) || (type === 'group' && activeGroup == id)) {
                        activeChat = null;
                        activeGroup = null;
                        updateChatHeader();
                        document.getElementById('messages').innerHTML = '';
                    }
                    
                    if (type === 'user') {
                        loadFriends(); 
                    }
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function deleteGroupById(groupId) {
            if (!confirm('Удалить группу? Это необратимо.')) return;
            
            const formData = new FormData();
            formData.append('action', 'delete_group');
            formData.append('group_id', groupId);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    groups = groups.filter(g => g.id != groupId);
                    updateChatList();
                    if (activeGroup == groupId) {
                        activeGroup = null;
                        updateChatHeader();
                        document.getElementById('messages').innerHTML = '';
                    }
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function openChat(userId) {
            activeChat = userId;
            activeGroup = null;
            updateChatHeader();
            loadMessages();
            updateChatList();
            document.getElementById('groupInfoBtn').style.display = 'none';
            document.getElementById('chatActionsBtn').style.display = 'flex';
            if (window.innerWidth <= 768) toggleSidebar();
        }
        
        function openGroup(groupId) {
            activeGroup = groupId;
            activeChat = null;
            updateChatHeader();
            loadMessages();
            updateChatList();
            document.getElementById('groupInfoBtn').style.display = 'flex';
            document.getElementById('chatActionsBtn').style.display = 'none';
            if (window.innerWidth <= 768) toggleSidebar();
        }
        
        function updateChatHeader() {
            const title = document.getElementById('chatTitle');
            const status = document.getElementById('chatStatus');
            const avatar = document.getElementById('chatAvatar');
            
            if (activeGroup) {
                const group = groups.find(g => g.id == activeGroup);
                title.textContent = group ? group.name : 'Группа';
                status.textContent = 'Групповой чат';
                avatar.textContent = '#';
            } else if (activeChat) {
                const friend = friends.find(f => f.id == activeChat);
                title.textContent = friend ? friend.username : 'Пользователь';
                status.textContent = friend && friend.status === 'online' ? 'В сети' : 'Офлайн';
                avatar.textContent = friend ? friend.username[0].toUpperCase() : '👤';
            } else {
                title.textContent = 'Выберите чат';
                status.textContent = 'Начните общение';
                avatar.textContent = '👤';
                document.getElementById('groupInfoBtn').style.display = 'none';
                document.getElementById('chatActionsBtn').style.display = 'none';
            }
        }
        
        function showChatActions() {
            document.getElementById('chatActionsModal').style.display = 'flex';
        }
        
        function deleteChat() {
            if (!confirm('Удалить чат? Это также удалит пользователя из друзей. Для нового общения нужно будет снова отправить запрос в друзья.')) return;
            
            const formData = new FormData();
            formData.append('action', 'delete_chat');
            if (activeGroup) {
                formData.append('group_id', activeGroup);
            } else {
                formData.append('chat_with', activeChat);
            }
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('chatActionsModal');
                    if (activeGroup) {
                        groups = groups.filter(g => g.id != activeGroup);
                    } else {
                        friends = friends.filter(f => f.id != activeChat);
                    }
                    activeChat = null;
                    activeGroup = null;
                    updateChatList();
                    updateChatHeader();
                    document.getElementById('messages').innerHTML = '';
                    
                    loadFriends();
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function loadMessages() {
            if (!activeChat && !activeGroup) return;
            
            const formData = new FormData();
            formData.append('action', 'get_messages');
            formData.append('csrf_token', csrfToken);
            
            if (activeGroup) {
                formData.append('group_id', activeGroup);
            } else {
                formData.append('chat_with', activeChat);
            }
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (JSON.stringify(messages) !== JSON.stringify(data.messages)) {
                        messages = data.messages;
                        displayMessages();
                    }
                }
            })
            .catch(error => console.error('Error loading messages:', error));
        }
        
        function loadMoreMessages() {
            if (!activeChat && !activeGroup || messages.length === 0) return;
            
            const formData = new FormData();
            formData.append('action', 'get_messages');
            formData.append('before_id', messages[0].id);
            formData.append('csrf_token', csrfToken);
            
            if (activeGroup) {
                formData.append('group_id', activeGroup);
            } else {
                formData.append('chat_with', activeChat);
            }
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success && data.messages.length > 0) {
                    messages = [...data.messages, ...messages];
                    displayMessages(true);
                }
            })
            .catch(error => console.error('Error loading more messages:', error));
        }
        
        function displayMessages(keepScroll = false) {
            const container = document.getElementById('messages');
            const oldScrollHeight = container.scrollHeight;
            const oldScrollTop = container.scrollTop;
            
            let html = '';
            let lastDate = null;
            
            messages.forEach(msg => {
                const msgDate = new Date(msg.sent_at).toDateString();
                if (msgDate !== lastDate) {
                    html += `<div style="text-align: center; margin: 10px 0; color: var(--text-tertiary); font-size: 0.8rem;">${formatDate(msg.sent_at)}</div>`;
                    lastDate = msgDate;
                }
                
                const isOwn = msg.sender_id == currentUser.id;
                const time = new Date(msg.sent_at).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
                
                html += `
                    <div class="message-wrapper ${isOwn ? 'own' : ''}" data-message-id="${msg.id}" ondblclick="selectMessage(${msg.id})" oncontextmenu="event.preventDefault(); selectMessage(${msg.id})">
                        <div class="message-avatar">
                            ${msg.username ? escapeHtml(msg.username[0].toUpperCase()) : '👤'}
                        </div>
                        <div class="message-content">
                            <div class="message-sender">${isOwn ? 'Вы' : escapeHtml(msg.username)}</div>
                            ${msg.type === 'image' ? `
                                <img src="${UPLOAD_DIR}${escapeHtml(msg.file_path)}" class="message-image" onclick="event.stopPropagation(); showImagePreview('${UPLOAD_DIR}${escapeHtml(msg.file_path)}')" alt="Image" loading="lazy">
                            ` : msg.type === 'file' ? `
                                <div class="message-file" onclick="event.stopPropagation(); downloadFile('${escapeHtml(msg.file_path)}')">
                                    <span>📎</span>
                                    <span style="flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">${escapeHtml(msg.file_name)}</span>
                                    <span style="font-size: 0.7rem;">${formatFileSize(msg.file_size)}</span>
                                </div>
                            ` : `
                                <div class="message-text">${escapeHtml(msg.message)}</div>
                            `}
                            <div class="message-reactions" id="reactions-${msg.id}"></div>
                            <div class="message-time">
                                ${time}
                                ${msg.is_edited ? ' (ред.)' : ''}
                                ${activeGroup ? (msg.read_count > 1 ? ` ✓${msg.read_count}` : '') : (msg.read_count > 0 ? ' ✓' : '')}
                            </div>
                        </div>
                    </div>
                `;
            });
            
            container.innerHTML = html;
            
            messages.forEach(msg => {
                loadReactions(msg.id);
            });
            
            if (keepScroll) {
                container.scrollTop = container.scrollHeight - oldScrollHeight + oldScrollTop;
            } else {
                container.scrollTop = container.scrollHeight;
            }
        }
        
        function loadReactions(messageId) {
            const formData = new FormData();
            formData.append('action', 'get_reactions');
            formData.append('message_id', messageId);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayReactions(messageId, data.reactions);
                }
            })
            .catch(error => console.error('Error loading reactions:', error));
        }
        
        function displayReactions(messageId, reactions) {
            const container = document.getElementById(`reactions-${messageId}`);
            if (!container) return;
            
            if (reactions.length === 0) {
                container.innerHTML = '';
                return;
            }
            
            const reactionGroups = {};
            reactions.forEach(r => {
                if (!reactionGroups[r.reaction]) {
                    reactionGroups[r.reaction] = [];
                }
                reactionGroups[r.reaction].push(r.username);
            });
            
            let html = '';
            for (const [reaction, users] of Object.entries(reactionGroups)) {
                html += `
                    <div class="reaction-badge" onclick="showReactions('${messageId}', '${escapeHtml(reaction)}')">
                        ${escapeHtml(reaction)} ${users.length}
                    </div>
                `;
            }
            
            container.innerHTML = html;
        }
        
        function showReactions(messageId, reaction) {
            const formData = new FormData();
            formData.append('action', 'get_reactions');
            formData.append('message_id', messageId);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const filtered = data.reactions.filter(r => r.reaction === reaction);
                    let html = '<h4 style="margin-bottom: 10px;">' + escapeHtml(reaction) + '</h4>';
                    filtered.forEach(r => {
                        html += `<div style="padding: 8px; border-bottom: 1px solid var(--border-color);">${escapeHtml(r.username)}</div>`;
                    });
                    document.getElementById('reactionsList').innerHTML = html;
                    document.getElementById('reactionsModal').style.display = 'flex';
                }
            })
            .catch(error => console.error('Error loading reactions:', error));
        }
        
        function selectMessage(messageId) {
            selectedMessageId = messageId;
            const msg = messages.find(m => m.id == messageId);
            if (msg && msg.sender_id == currentUser.id) {
                document.getElementById('messageActionsModal').style.display = 'flex';
            } else {
                addReaction(messageId);
            }
        }
        
        function addReaction(messageId) {
            const reaction = prompt('Введите реакцию (один символ или эмодзи):');
            if (!reaction) return;
            
            const formData = new FormData();
            formData.append('action', 'add_reaction');
            formData.append('message_id', messageId);
            formData.append('reaction', reaction);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadReactions(messageId);
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function editMessage() {
            const msg = messages.find(m => m.id == selectedMessageId);
            if (!msg) return;
            
            document.getElementById('editMessageText').value = msg.message;
            document.getElementById('editMessageModal').style.display = 'flex';
            hideModal('messageActionsModal');
        }
        
        function saveEditedMessage() {
            const newText = document.getElementById('editMessageText').value.trim();
            if (!newText) return;
            
            const formData = new FormData();
            formData.append('action', 'edit_message');
            formData.append('message_id', selectedMessageId);
            formData.append('message', newText);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('editMessageModal');
                    loadMessages();
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function deleteMessage(forEveryone) {
            const formData = new FormData();
            formData.append('action', 'delete_message');
            formData.append('message_id', selectedMessageId);
            formData.append('for_everyone', forEveryone);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('messageActionsModal');
                    loadMessages();
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function sendMessage() {
            const input = document.getElementById('messageInput');
            const message = input.value.trim();
            
            if (!message || (!activeChat && !activeGroup)) return;
            
            const formData = new FormData();
            formData.append('action', 'send_message');
            formData.append('message', message);
            formData.append('csrf_token', csrfToken);
            
            if (activeGroup) {
                formData.append('group_id', activeGroup);
            } else {
                formData.append('receiver_id', activeChat);
            }
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    input.value = '';
                    input.style.height = 'auto';
                    messages.push(data.message);
                    displayMessages();
                } else {
                    alert(data.error || 'Ошибка отправки');
                }
            })
            .catch(error => console.error('Send error:', error));
        }
        
        function uploadFile() {
            const fileInput = document.getElementById('fileInput');
            const file = fileInput.files[0];
            
            if (!file || (!activeChat && !activeGroup)) return;
            
            const formData = new FormData();
            formData.append('action', 'upload_file');
            formData.append('file', file);
            formData.append('csrf_token', csrfToken);
            
            if (activeGroup) {
                formData.append('group_id', activeGroup);
            } else {
                formData.append('receiver_id', activeChat);
            }
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    fileInput.value = '';
                    messages.push(data.message);
                    displayMessages();
                } else {
                    alert(data.error || 'Ошибка загрузки');
                }
            })
            .catch(error => console.error('Upload error:', error));
        }
        
        function showCreateGroupModal() {
            document.getElementById('createGroupModal').style.display = 'flex';
        }
        
        function createGroup() {
            const name = document.getElementById('groupName').value.trim();
            const description = document.getElementById('groupDescription').value.trim();
            
            if (!name) {
                alert('Введите название группы');
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'create_group');
            formData.append('name', name);
            formData.append('description', description);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('createGroupModal');
                    document.getElementById('groupName').value = '';
                    document.getElementById('groupDescription').value = '';
                    loadGroups();
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function showGroupInfo() {
            if (!activeGroup) return;
            
            const formData = new FormData();
            formData.append('action', 'get_group_members');
            formData.append('group_id', activeGroup);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    displayGroupInfo(data.members);
                }
            })
            .catch(error => console.error('Error loading members:', error));
        }
        
        function displayGroupInfo(members) {
            const group = groups.find(g => g.id == activeGroup);
            const isAdmin = group.user_role === 'admin' || group.creator_id == currentUser.id;
            
            document.getElementById('groupInfoName').textContent = group.name;
            document.getElementById('groupDescriptionDisplay').textContent = group.description || 'Нет описания';
            
            let membersHtml = '';
            members.forEach(member => {
                const isOnline = member.status === 'online';
                membersHtml += `
                    <div class="member-item">
                        <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
                            <div class="avatar" style="width: 36px; height: 36px; font-size: 1rem; position: relative;">
                                ${escapeHtml(member.username[0].toUpperCase())}
                                ${isOnline ? '<span class="online-status-dot" style="position: absolute; bottom: 2px; right: 2px;"></span>' : ''}
                            </div>
                            <div style="min-width: 0;">
                                <div style="font-weight: 500; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                    ${escapeHtml(member.username)}
                                </div>
                                <span class="member-role">${member.role === 'admin' ? 'Админ' : 'Участник'}</span>
                            </div>
                        </div>
                    </div>
                `;
            });
            
            document.getElementById('groupMembersList').innerHTML = membersHtml;
            
            let friendsHtml = '';
            friends.forEach(friend => {
                const isInGroup = members.some(m => m.id == friend.id);
                if (!isInGroup) {
                    friendsHtml += `
                        <div class="member-item">
                            <div style="display: flex; align-items: center; gap: 10px; min-width: 0;">
                                <div class="avatar" style="width: 36px; height: 36px;">${escapeHtml(friend.username[0].toUpperCase())}</div>
                                <div style="font-weight: 500; color: var(--text-primary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                                    ${escapeHtml(friend.username)}
                                </div>
                            </div>
                            <button class="modal-btn primary" onclick="inviteToGroup(${friend.id})" style="padding: 8px 16px;">➕</button>
                        </div>
                    `;
                }
            });
            
            document.getElementById('friendsToInvite').innerHTML = friendsHtml || '<p style="color: var(--text-tertiary);">Нет друзей для приглашения</p>';
            
            document.getElementById('leaveGroupBtn').style.display = group.creator_id == currentUser.id ? 'none' : 'inline-block';
            document.getElementById('deleteGroupBtn').style.display = (group.creator_id == currentUser.id || isAdmin) ? 'inline-block' : 'none';
            
            document.getElementById('groupInfoModal').style.display = 'flex';
        }
        
        function inviteToGroup(userId) {
            const formData = new FormData();
            formData.append('action', 'invite_to_group');
            formData.append('group_id', activeGroup);
            formData.append('user_id', userId);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Приглашение отправлено!');
                    showGroupInfo();
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function leaveGroup() {
            if (!confirm('Покинуть группу?')) return;
            
            const formData = new FormData();
            formData.append('action', 'leave_group');
            formData.append('group_id', activeGroup);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('groupInfoModal');
                    groups = groups.filter(g => g.id != activeGroup);
                    activeGroup = null;
                    updateChatList();
                    updateChatHeader();
                    document.getElementById('messages').innerHTML = '';
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function deleteGroup() {
            if (!confirm('Удалить группу?')) return;
            
            const formData = new FormData();
            formData.append('action', 'delete_group');
            formData.append('group_id', activeGroup);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    hideModal('groupInfoModal');
                    groups = groups.filter(g => g.id != activeGroup);
                    activeGroup = null;
                    updateChatList();
                    updateChatHeader();
                    document.getElementById('messages').innerHTML = '';
                } else {
                    alert(data.error || 'Ошибка');
                }
            })
            .catch(error => console.error('Error:', error));
        }
        
        function showImagePreview(src) {
            document.getElementById('previewImage').src = src;
            document.getElementById('imagePreviewModal').style.display = 'flex';
        }
        
        function downloadFile(filename) {
            window.location.href = UPLOAD_DIR + filename;
        }
        
        function formatFileSize(bytes) {
            if (!bytes) return '';
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
        
        function formatDate(dateStr) {
            const date = new Date(dateStr);
            const today = new Date();
            const yesterday = new Date(today);
            yesterday.setDate(yesterday.getDate() - 1);
            
            if (date.toDateString() === today.toDateString()) {
                return 'Сегодня';
            } else if (date.toDateString() === yesterday.toDateString()) {
                return 'Вчера';
            } else {
                return date.toLocaleDateString('ru-RU', { day: 'numeric', month: 'long' });
            }
        }
        
        function switchTab(tab) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            
            const items = document.querySelectorAll('.chat-item');
            items.forEach(item => {
                if (tab === 'groups' && item.getAttribute('onclick')?.includes('openGroup')) {
                    item.style.display = 'flex';
                } else if (tab === 'groups') {
                    item.style.display = 'none';
                } else if (tab === 'contacts' && item.getAttribute('onclick')?.includes('openChat')) {
                    item.style.display = 'flex';
                } else if (tab === 'contacts') {
                    item.style.display = 'none';
                } else {
                    item.style.display = 'flex';
                }
            });
        }
        
        function handleKeyPress(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
            if (e.key === 'Escape') {
                document.getElementById('searchResults').style.display = 'none';
                document.getElementById('emojiPicker').style.display = 'none';
            }
        }
        
        function hideModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }
        
        function logout() {
            const formData = new FormData();
            formData.append('action', 'logout');
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(() => {
                window.location.reload();
            })
            .catch(error => console.error('Logout error:', error));
        }
        
        function escapeHtml(unsafe) {
            if (!unsafe) return '';
            return unsafe
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }
        
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
            if (!event.target.closest('.emoji-picker') && !event.target.closest('.emoji-btn')) {
                document.getElementById('emojiPicker').style.display = 'none';
            }
        }
    </script>
</body>
</html>
<?php
register_shutdown_function(function() use ($user_id, $dbManager) {
    if (isset($user_id)) {
        $stmt = $dbManager->prepare("UPDATE users SET status = 'offline', last_seen = CURRENT_TIMESTAMP WHERE id = :id");
        $stmt->bindValue(':id', $user_id);
        $stmt->execute();
    }
});
?>
