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
define('AVATAR_DIR', 'uploads/avatars/');
define('MAX_FILE_SIZE', 10 * 1024 * 1024);
define('MAX_IMAGE_SIZE', 5 * 1024 * 1024);
define('MAX_AVATAR_SIZE', 3 * 1024 * 1024);

// === LIMITS ===
define('MAX_MESSAGE_LENGTH', 2000);
define('MIN_PASSWORD_LENGTH', 8);
define('MAX_PASSWORD_LENGTH', 32);
define('MIN_USERNAME_LENGTH', 3);
define('MAX_USERNAME_LENGTH', 24);
define('MAX_EMAIL_LENGTH', 30);
define('MAX_GROUP_NAME_LENGTH', 24);
define('MAX_GROUP_DESC_LENGTH', 500);

// === RATE LIMITS ===
define('RATE_LIMIT_MESSAGES', 15);
define('RATE_LIMIT_MESSAGES_BURST', 5);
define('RATE_LIMIT_REGISTRATIONS', 3);
define('RATE_LIMIT_FILE_UPLOADS', 5);
define('RATE_LIMIT_LOGIN_ATTEMPTS', 5);
define('SPAM_DETECT_THRESHOLD', 0.8);

define('BCRYPT_COST', 12);
define('TURNSTILE_SITE_KEY', ''); // Cloudflare captcha
define('TURNSTILE_SECRET_KEY', ''); // Cloudflare captcha
define('ENCRYPTION_KEY', ''); // Database encryption key
define('CACHE_ENABLED', true);
define('CACHE_TTL', 300);
define('SEARCH_CACHE_TTL', 60);
define('ALLOWED_IMAGE_TYPES', ['image/jpeg', 'image/png', 'image/gif', 'image/webp']);
define('ALLOWED_FILE_TYPES', ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain']);

foreach ([UPLOAD_DIR, AVATAR_DIR] as $dir) {
    if (!file_exists($dir)) mkdir($dir, 0755, true);
}

class Cache {
    private static $store = [];
    private static $timestamps = [];
    private static $maxItems = 1000;
    
    public static function get($key) {
        if (!CACHE_ENABLED) return null;
        if (isset(self::$store[$key]) && isset(self::$timestamps[$key])) {
            if (time() - self::$timestamps[$key] < CACHE_TTL) return self::$store[$key];
            unset(self::$store[$key], self::$timestamps[$key]);
        }
        return null;
    }
    
    public static function set($key, $value) {
        if (!CACHE_ENABLED) return;
        if (count(self::$store) >= self::$maxItems) {
            asort(self::$timestamps);
            foreach (array_slice(array_keys(self::$timestamps), 0, 100) as $k) {
                unset(self::$store[$k], self::$timestamps[$k]);
            }
        }
        self::$store[$key] = $value;
        self::$timestamps[$key] = time();
    }
    
    public static function clear($prefix = null) {
        if ($prefix === null) { self::$store = []; self::$timestamps = []; return; }
        foreach (array_keys(self::$store) as $key) {
            if (strpos($key, $prefix) === 0) unset(self::$store[$key], self::$timestamps[$key]);
        }
    }
    
    public static function remember($key, $callback, $ttl = null) {
        $value = self::get($key);
        if ($value !== null) return $value;
        $value = $callback();
        self::set($key, $value);
        return $value;
    }
}

class Encryption {
    private static $key;
    private static $method = 'aes-256-gcm';
    
    public static function init($key) { self::$key = hash('sha256', $key, true); }
    
    public static function encrypt($data) {
        if (empty($data)) return '';
        $ivlen = openssl_cipher_iv_length(self::$method);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $tag = '';
        $encrypted = openssl_encrypt($data, self::$method, self::$key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($encrypted === false) throw new Exception('Encryption failed');
        return base64_encode($iv . $tag . $encrypted);
    }
    
    public static function decrypt($data) {
        if (empty($data)) return '';
        $decoded = base64_decode($data);
        if ($decoded === false) return $data;
        $ivlen = openssl_cipher_iv_length(self::$method);
        if (strlen($decoded) < $ivlen + 16) return $data;
        $iv = substr($decoded, 0, $ivlen);
        $tag = substr($decoded, $ivlen, 16);
        $encrypted = substr($decoded, $ivlen + 16);
        $decrypted = openssl_decrypt($encrypted, self::$method, self::$key, OPENSSL_RAW_DATA, $iv, $tag);
        return $decrypted === false ? $data : $decrypted;
    }
    
    public static function encryptForSearch($data) { return hash('sha256', self::$key . $data); }
    public static function encryptForPrefix($data) { return substr(hash('sha256', self::$key . $data), 0, 8); }
}

Encryption::init(ENCRYPTION_KEY);

class SpamDetector {
    private static $recentMessages = [];
    private static $messageCounts = [];
    
    // Проверка на спам: частота + повторяющийся контент
    public static function check($userId, $message) {
        $now = time();
        $key = 'spam_' . $userId;
        
        if (!isset(self::$recentMessages[$key])) {
            self::$recentMessages[$key] = [];
            self::$messageCounts[$key] = [];
        }
        
        // Очищаем старые записи (старше 60 секунд)
        self::$recentMessages[$key] = array_filter(
            self::$recentMessages[$key],
            fn($item) => $now - $item['time'] < 60
        );
        self::$messageCounts[$key] = array_filter(
            self::$messageCounts[$key],
            fn($t) => $now - $t < 5
        );
        
        // Проверка на быстрый флуд (5 сообщений за 5 секунд)
        if (count(self::$messageCounts[$key]) >= RATE_LIMIT_MESSAGES_BURST) {
            return ['blocked' => true, 'reason' => 'Вы отправляете сообщения слишком быстро. Подождите несколько секунд.'];
        }
        
        // Проверка на повторяющийся контент
        if (!empty($message)) {
            $msgLower = mb_strtolower(trim($message));
            $duplicateCount = 0;
            
            foreach (self::$recentMessages[$key] as $recent) {
                similar_text($msgLower, $recent['text'], $similarity);
                if ($similarity >= SPAM_DETECT_THRESHOLD * 100) {
                    $duplicateCount++;
                }
            }
            
            if ($duplicateCount >= 3) {
                return ['blocked' => true, 'reason' => 'Обнаружен спам: слишком много одинаковых сообщений.'];
            }
        }
        
        // Проверка лимита сообщений (15 в минуту)
        if (count(self::$recentMessages[$key]) >= RATE_LIMIT_MESSAGES) {
            return ['blocked' => true, 'reason' => 'Слишком много сообщений. Лимит: ' . RATE_LIMIT_MESSAGES . ' в минуту.'];
        }
        
        // Записываем текущее сообщение
        self::$recentMessages[$key][] = ['time' => $now, 'text' => mb_strtolower(trim($message))];
        self::$messageCounts[$key][] = $now;
        
        return ['blocked' => false];
    }
}

class Security {
    private static $rateLimitCache = [];
    
    public static function checkServerLoad() {
        if (function_exists('sys_getloadavg')) {
            $load = sys_getloadavg();
            if ($load[0] > 10) {
                http_response_code(503);
                header('Retry-After: 30');
                die(json_encode(['error' => 'Сервер перегружен. Попробуйте позже.']));
            }
        }
        return true;
    }
    
    public static function sanitizeInput($data) {
        if (is_array($data)) return array_map([self::class, 'sanitizeInput'], $data);
        return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
    }
    
    public static function generateCSRFToken() {
        if (empty($_SESSION['csrf_token'])) $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        return $_SESSION['csrf_token'];
    }
    
    public static function validateCSRFToken($token) {
        return hash_equals($_SESSION['csrf_token'] ?? '', $token);
    }
    
    public static function verifyTurnstile($token) {
        if (TURNSTILE_SECRET_KEY === '1x0000000000000000000000000000000AA') return true;
        $cacheKey = 'turnstile_' . md5($token);
        $cached = Cache::get($cacheKey);
        if ($cached !== null) return $cached;
        $clientIP = self::getClientIP();
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => 'https://challenges.cloudflare.com/turnstile/v0/siteverify',
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query(['secret' => TURNSTILE_SECRET_KEY, 'response' => $token, 'remoteip' => $clientIP]),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);
        $response = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);
        if ($error) return false;
        $data = json_decode($response, true);
        $result = $data['success'] ?? false;
        Cache::set($cacheKey, $result);
        return $result;
    }
    
    public static function checkRateLimit($action, $identifier, $limit, $period = 60) {
        $key = $action . '_' . $identifier;
        $now = time();
        if (!isset(self::$rateLimitCache[$key])) self::$rateLimitCache[$key] = [];
        self::$rateLimitCache[$key] = array_filter(self::$rateLimitCache[$key], fn($t) => $t > $now - $period);
        if (count(self::$rateLimitCache[$key]) >= $limit) return false;
        self::$rateLimitCache[$key][] = $now;
        return true;
    }
    
    public static function checkBruteforce($ip, $username) {
        $key = 'bruteforce_' . $ip . '_' . $username;
        $attempts = $_SESSION[$key] ?? ['count' => 0, 'first_attempt' => time()];
        if (time() - $attempts['first_attempt'] > 900) $attempts = ['count' => 0, 'first_attempt' => time()];
        $attempts['count']++;
        $_SESSION[$key] = $attempts;
        return $attempts['count'] <= RATE_LIMIT_LOGIN_ATTEMPTS;
    }
    
    public static function validateFile($file, $type = 'any') {
        if ($file['error'] !== UPLOAD_ERR_OK) return ['error' => 'Ошибка загрузки файла'];
        $maxSize = ($type === 'image' || $type === 'avatar') ? MAX_IMAGE_SIZE : MAX_FILE_SIZE;
        if ($type === 'avatar') $maxSize = MAX_AVATAR_SIZE;
        if ($file['size'] > $maxSize) return ['error' => 'Файл слишком большой. Максимум: ' . ($maxSize / 1024 / 1024) . 'MB'];
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mimeType = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        if (in_array($type, ['image', 'avatar'])) {
            if (!in_array($mimeType, ALLOWED_IMAGE_TYPES)) return ['error' => 'Недопустимый формат изображения. Разрешены: JPG, PNG, GIF, WEBP'];
            if (!getimagesize($file['tmp_name'])) return ['error' => 'Файл не является изображением'];
        } else {
            if (!in_array($mimeType, ALLOWED_FILE_TYPES)) return ['error' => 'Недопустимый тип файла'];
        }
        $content = file_get_contents($file['tmp_name']);
        $dangerousPatterns = ['/<\?php/i', '/<script/i', '/eval\(/i', '/base64_decode/i', '/system\(/i', '/exec\(/i', '/shell_exec\(/i'];
        foreach ($dangerousPatterns as $pattern) {
            if (preg_match($pattern, $content)) return ['error' => 'Файл содержит подозрительный код'];
        }
        return ['success' => true, 'mime_type' => $mimeType];
    }
    
    public static function processUpload($file, $type = 'any') {
        $validation = self::validateFile($file, $type);
        if (isset($validation['error'])) return $validation;
        $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
        $safeExtension = preg_replace('/[^a-zA-Z0-9]/', '', $extension);
        $filename = bin2hex(random_bytes(16)) . '_' . time() . '.' . $safeExtension;
        $dir = ($type === 'avatar') ? AVATAR_DIR : UPLOAD_DIR;
        $filepath = $dir . $filename;
        if (move_uploaded_file($file['tmp_name'], $filepath)) {
            chmod($filepath, 0644);
            if (in_array($type, ['image', 'avatar']) && $file['size'] > 512 * 1024) {
                self::compressImage($filepath, $filepath, $type === 'avatar' ? 90 : 80);
            }
            if ($type === 'avatar') {
                self::cropAvatarToSquare($filepath);
            }
            return ['success' => true, 'filename' => $filename, 'path' => $filepath, 'size' => $file['size'], 'original_name' => $file['name'], 'mime_type' => $validation['mime_type']];
        }
        return ['error' => 'Ошибка сохранения файла'];
    }
    
    private static function cropAvatarToSquare($filepath) {
        $info = getimagesize($filepath);
        if (!$info) return;
        
        switch ($info['mime']) {
            case 'image/jpeg': $src = imagecreatefromjpeg($filepath); break;
            case 'image/png': $src = imagecreatefrompng($filepath); break;
            case 'image/gif': $src = imagecreatefromgif($filepath); break;
            case 'image/webp': $src = imagecreatefromwebp($filepath); break;
            default: return;
        }
        
        $width = imagesx($src);
        $height = imagesy($src);
        $size = min($width, $height);
        $x = (int)(($width - $size) / 2);
        $y = (int)(($height - $size) / 2);
        $targetSize = min($size, 256);
        
        $dst = imagecreatetruecolor($targetSize, $targetSize);
        if ($info['mime'] === 'image/png') {
            imagealphablending($dst, false);
            imagesavealpha($dst, true);
        }
        
        imagecopyresampled($dst, $src, 0, 0, $x, $y, $targetSize, $targetSize, $size, $size);
        
        switch ($info['mime']) {
            case 'image/jpeg': imagejpeg($dst, $filepath, 90); break;
            case 'image/png': imagepng($dst, $filepath, 8); break;
            case 'image/gif': imagegif($dst, $filepath); break;
            case 'image/webp': imagewebp($dst, $filepath, 90); break;
        }
        
        imagedestroy($src);
        imagedestroy($dst);
    }
    
    private static function compressImage($source, $destination, $quality) {
        $info = getimagesize($source);
        switch ($info['mime']) {
            case 'image/jpeg': $img = imagecreatefromjpeg($source); imagejpeg($img, $destination, $quality); break;
            case 'image/png': $img = imagecreatefrompng($source); imagepng($img, $destination, round(9 * $quality / 100)); break;
            case 'image/gif': $img = imagecreatefromgif($source); imagegif($img, $destination); break;
            case 'image/webp': $img = imagecreatefromwebp($source); imagewebp($img, $destination, $quality); break;
        }
        if (isset($img)) imagedestroy($img);
    }
    
    public static function getClientIP() {
        if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = $_SERVER['HTTP_CF_CONNECTING_IP'];
            if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
        }
        foreach (['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP'] as $header) {
            if (isset($_SERVER[$header])) {
                $ip = trim(explode(',', $_SERVER[$header])[0]);
                if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }
    
    public static function validatePassword($password) {
        $len = mb_strlen($password);
        if ($len < MIN_PASSWORD_LENGTH) return 'Пароль должен быть не менее ' . MIN_PASSWORD_LENGTH . ' символов';
        if ($len > MAX_PASSWORD_LENGTH) return 'Пароль не должен превышать ' . MAX_PASSWORD_LENGTH . ' символов';
        if (!preg_match('/[A-Z]/', $password)) return 'Пароль должен содержать хотя бы одну заглавную букву';
        if (!preg_match('/[a-z]/', $password)) return 'Пароль должен содержать хотя бы одну строчную букву';
        if (!preg_match('/[0-9]/', $password)) return 'Пароль должен содержать хотя бы одну цифру';
        $common = ['password', '12345678', 'qwerty123', 'admin123', 'password1', '11111111'];
        if (in_array(strtolower($password), $common)) return 'Пароль слишком простой. Придумайте что-то посложнее';
        return true;
    }
    
    public static function validateUsername($username) {
        $len = mb_strlen($username);
        if ($len < MIN_USERNAME_LENGTH || $len > MAX_USERNAME_LENGTH) return 'Имя пользователя должно быть от ' . MIN_USERNAME_LENGTH . ' до ' . MAX_USERNAME_LENGTH . ' символов';
        if (!preg_match('/^[a-zA-Z0-9_]+$/', $username)) return 'Имя пользователя может содержать только латинские буквы, цифры и _';
        $reserved = ['admin', 'root', 'system', 'support', 'moderator', 'mod', 'owner', 'bot'];
        if (in_array(strtolower($username), $reserved)) return 'Это имя пользователя зарезервировано';
        return true;
    }
    
    public static function validateEmail($email) {
        if (mb_strlen($email) > MAX_EMAIL_LENGTH) return 'Email не должен превышать ' . MAX_EMAIL_LENGTH . ' символов';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) return 'Неверный формат email';
        return true;
    }
    
    public static function validateMessage($message) {
        $len = mb_strlen($message);
        if ($len === 0) return 'Сообщение не может быть пустым';
        if ($len > MAX_MESSAGE_LENGTH) return 'Сообщение слишком длинное. Максимум: ' . MAX_MESSAGE_LENGTH . ' символов (сейчас: ' . $len . ')';
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
        if (file_exists(DB_FILE)) chmod(DB_FILE, 0600);
        $this->db = new SQLite3(DB_FILE);
        if (file_exists(DB_FILE)) chmod(DB_FILE, 0600);
        $this->db->exec("PRAGMA foreign_keys = ON;");
        $this->db->exec("PRAGMA journal_mode = WAL;");
        $this->db->exec("PRAGMA synchronous = NORMAL;");
        $this->db->exec("PRAGMA cache_size = 10000;");
        $this->db->exec("PRAGMA temp_store = MEMORY;");
        $this->db->exec("PRAGMA busy_timeout = 10000;");
        $this->initTables();
    }
    
    private function executeWithRetry($callback) {
        for ($i = 0; $i < $this->maxRetries; $i++) {
            try {
                return $callback();
            } catch (Exception $e) {
                $isLocked = strpos($e->getMessage(), 'locked') !== false;
                if (!$isLocked || $i === $this->maxRetries - 1) throw $e;
                usleep($this->retryDelay * pow(2, $i));
            }
        }
    }
    
    public function exec($sql) { return $this->executeWithRetry(fn() => $this->db->exec($sql)); }
    
    public function query($sql, $params = []) {
        return $this->executeWithRetry(function() use ($sql, $params) {
            $stmt = $this->prepare($sql);
            foreach ($params as $key => $value) $stmt->bindValue($key, $value);
            $result = $stmt->execute();
            $rows = [];
            while ($row = $result->fetchArray(SQLITE3_ASSOC)) $rows[] = $row;
            return $rows;
        });
    }
    
    public function querySingle($sql, $params = []) {
        $result = $this->query($sql, $params);
        return !empty($result) ? $result[0] : null;
    }
    
    public function queryValue($sql, $params = []) {
        $result = $this->query($sql, $params);
        if (!empty($result) && !empty($result[0])) return reset($result[0]);
        return null;
    }
    
    public function insert($sql, $params = []) {
        return $this->executeWithRetry(function() use ($sql, $params) {
            $stmt = $this->prepare($sql);
            foreach ($params as $key => $value) $stmt->bindValue($key, $value);
            $stmt->execute();
            return $this->db->lastInsertRowID();
        });
    }
    
    public function execute($sql, $params = []) {
        return $this->executeWithRetry(function() use ($sql, $params) {
            $stmt = $this->prepare($sql);
            foreach ($params as $key => $value) $stmt->bindValue($key, $value);
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
        if ($this->transactionLevel === 0) $this->exec("BEGIN IMMEDIATE TRANSACTION");
        $this->transactionLevel++;
        return true;
    }
    
    public function commitTransaction() {
        $this->transactionLevel--;
        if ($this->transactionLevel === 0) return $this->exec("COMMIT");
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
        
        // Индексы
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_sent_at ON messages(sent_at);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_id) WHERE receiver_id IS NOT NULL;");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_messages_group ON messages(group_id) WHERE group_id IS NOT NULL;");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_users_hash ON users(username_hash, email_hash);");
        $this->exec("CREATE INDEX IF NOT EXISTS idx_users_prefix ON users(username_prefix);");
        
        $this->migrateExistingData();
    }
    
    private function migrateExistingData() {
        try {
            $columns = array_column($this->query("PRAGMA table_info(users)"), 'name');
            if (!in_array('username_prefix', $columns)) {
                $this->transaction(function() {
                    $this->exec("ALTER TABLE users ADD COLUMN username_prefix TEXT");
                    foreach ($this->query("SELECT id, username_encrypted FROM users") as $row) {
                        $username = Encryption::decrypt($row['username_encrypted']);
                        $this->execute("UPDATE users SET username_prefix = :p WHERE id = :id",
                            [':p' => Encryption::encryptForPrefix($username), ':id' => $row['id']]);
                    }
                });
            }
        } catch (Exception $e) { error_log("Migration error: " . $e->getMessage()); }
    }
    
    public function getDb() { return $this->db; }
    
    public function searchUsers($query, $currentUserId, $limit = 20) {
        $prefix = Encryption::encryptForPrefix($query);
        return Cache::remember('search_' . $prefix . '_' . $currentUserId, function() use ($prefix, $query, $currentUserId, $limit) {
            $candidates = $this->query(
                "SELECT id, username_encrypted, status, avatar FROM users WHERE id != :uid AND username_prefix = :prefix ORDER BY last_seen DESC LIMIT :lim",
                [':uid' => $currentUserId, ':prefix' => $prefix, ':lim' => $limit * 3]
            );
            $result = [];
            foreach ($candidates as $row) {
                $username = Encryption::decrypt($row['username_encrypted']);
                if (stripos($username, $query) !== false) {
                    $row['username'] = $username;
                    unset($row['username_encrypted']);
                    $result[] = $row;
                    if (count($result) >= $limit) break;
                }
            }
            return $result;
        }, SEARCH_CACHE_TTL);
    }
    
    public function addReadReceipt($messageId, $userId) {
        try {
            $this->execute("INSERT OR IGNORE INTO read_receipts (message_id, user_id) VALUES (:m, :u)", [':m' => $messageId, ':u' => $userId]);
            return (int)$this->queryValue("SELECT COUNT(*) FROM read_receipts WHERE message_id = :m", [':m' => $messageId]);
        } catch (Exception $e) { return 0; }
    }
    
    public function getGroupReadCounts($groupId, $messageIds) {
        if (empty($messageIds)) return [];
        $placeholders = implode(',', array_fill(0, count($messageIds), '?'));
        $params = [];
        foreach ($messageIds as $i => $id) $params[$i + 1] = $id;
        $results = $this->query("SELECT message_id, COUNT(DISTINCT user_id) as count FROM read_receipts WHERE message_id IN ($placeholders) GROUP BY message_id", $params);
        $counts = [];
        foreach ($results as $row) $counts[$row['message_id']] = $row['count'];
        return $counts;
    }
    
    public function addRateLimit($ip, $action) {
        return $this->execute("INSERT INTO rate_limits (ip_address_encrypted, action_type) VALUES (:ip, :action)",
            [':ip' => Encryption::encrypt($ip), ':action' => $action]);
    }
    
    public function checkRateLimit($ip, $action, $limit, $period = 3600) {
        $count = $this->queryValue(
            "SELECT COUNT(*) FROM rate_limits WHERE ip_address_encrypted = :ip AND action_type = :action AND created_at > datetime('now', '-' || :period || ' seconds')",
            [':ip' => Encryption::encrypt($ip), ':action' => $action, ':period' => $period]
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

function getClientIP() { return Security::getClientIP(); }
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
                $cfToken = $_POST['cf-turnstile-response'] ?? '';
                
                if (!Security::verifyTurnstile($cfToken)) sendJsonResponse(['error' => 'Подтвердите, что вы не робот']);
                if (!Security::checkBruteforce($clientIP, $username)) sendJsonResponse(['error' => 'Слишком много попыток. Попробуйте через 15 минут.']);
                if (!Security::checkRateLimit('login', $clientIP, 10, 300)) sendJsonResponse(['error' => 'Слишком много попыток входа. Подождите 5 минут.']);
                
                $usernameHash = Encryption::encryptForSearch($username);
                $stmt = $dbManager->prepare("SELECT * FROM users WHERE username_hash = :h OR email_hash = :h");
                $stmt->bindValue(':h', $usernameHash);
                $user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                
                if ($user && $user['locked_until'] && strtotime($user['locked_until']) > time()) {
                    sendJsonResponse(['error' => 'Аккаунт временно заблокирован. Попробуйте позже.']);
                }
                
                if ($user && password_verify($password, $user['password'])) {
                    if (password_needs_rehash($user['password'], PASSWORD_BCRYPT, ['cost' => BCRYPT_COST])) {
                        $stmt = $dbManager->prepare("UPDATE users SET password = :p WHERE id = :id");
                        $stmt->bindValue(':p', password_hash($password, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]));
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
                    $stmt = $dbManager->prepare("INSERT INTO user_sessions (user_id, session_token, ip_address_encrypted, user_agent_encrypted, expires_at) VALUES (:uid, :tok, :ip, :ua, datetime('now', '+7 days'))");
                    $stmt->bindValue(':uid', $user['id']);
                    $stmt->bindValue(':tok', $sessionToken);
                    $stmt->bindValue(':ip', Encryption::encrypt($clientIP));
                    $stmt->bindValue(':ua', Encryption::encrypt($_SERVER['HTTP_USER_AGENT'] ?? ''));
                    $stmt->execute();
                    $_SESSION['session_token'] = $sessionToken;
                    
                    $stmt = $dbManager->prepare("UPDATE users SET status = 'online', last_seen = CURRENT_TIMESTAMP, ip_address_encrypted = :ip WHERE id = :id");
                    $stmt->bindValue(':ip', Encryption::encrypt($clientIP));
                    $stmt->bindValue(':id', $user['id']);
                    $stmt->execute();
                    
                    $user['username'] = Encryption::decrypt($user['username_encrypted']);
                    if ($user['email_encrypted']) $user['email'] = Encryption::decrypt($user['email_encrypted']);
                    unset($user['password'], $user['username_encrypted'], $user['email_encrypted'], $user['username_hash'], $user['email_hash'], $user['username_prefix'], $user['ip_address_encrypted']);
                    
                    sendJsonResponse(['success' => true, 'user' => $user, 'csrf_token' => Security::generateCSRFToken()]);
                } else {
                    if ($user) {
                        $stmt = $dbManager->prepare("UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = :id");
                        $stmt->bindValue(':id', $user['id']);
                        $stmt->execute();
                        $attempts = $dbManager->queryValue("SELECT failed_attempts FROM users WHERE id = :id", [':id' => $user['id']]);
                        if ($attempts >= RATE_LIMIT_LOGIN_ATTEMPTS) {
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
                $cfToken = $_POST['cf-turnstile-response'] ?? '';
                
                if (!Security::verifyTurnstile($cfToken)) sendJsonResponse(['error' => 'Подтвердите, что вы не робот']);
                
                $usernameValidation = Security::validateUsername($username);
                if ($usernameValidation !== true) sendJsonResponse(['error' => $usernameValidation]);
                
                $passwordValidation = Security::validatePassword($password);
                if ($passwordValidation !== true) sendJsonResponse(['error' => $passwordValidation]);
                
                if ($email) {
                    $emailValidation = Security::validateEmail($email);
                    if ($emailValidation !== true) sendJsonResponse(['error' => $emailValidation]);
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
                
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("INSERT INTO users (username_encrypted, username_hash, username_prefix, email_encrypted, email_hash, password, ip_address_encrypted) VALUES (:ue, :uh, :up, :ee, :eh, :p, :ip)");
                    $stmt->bindValue(':ue', $usernameEncrypted);
                    $stmt->bindValue(':uh', $usernameHash);
                    $stmt->bindValue(':up', $usernamePrefix);
                    $stmt->bindValue(':ee', $emailEncrypted);
                    $stmt->bindValue(':eh', $emailHash);
                    $stmt->bindValue(':p', $hashedPassword);
                    $stmt->bindValue(':ip', Encryption::encrypt($clientIP));
                    $stmt->execute();
                    $dbManager->addRateLimit($clientIP, 'register');
                    $dbManager->commitTransaction();
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) {
                    $dbManager->rollbackTransaction();
                    if (strpos($e->getMessage(), 'username_hash') !== false) sendJsonResponse(['error' => 'Это имя пользователя уже занято']);
                    else if (strpos($e->getMessage(), 'email_hash') !== false) sendJsonResponse(['error' => 'Этот email уже используется']);
                    else { error_log("Registration error: " . $e->getMessage()); sendJsonResponse(['error' => 'Ошибка регистрации. Попробуйте позже.']); }
                }
                break;
                
            // === НАСТРОЙКИ АККАУНТА ===
            case 'update_account':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                
                $newEmail = trim($_POST['email'] ?? '');
                $newPassword = $_POST['new_password'] ?? '';
                $currentPassword = $_POST['current_password'] ?? '';
                
                // Проверяем текущий пароль
                $userRow = $dbManager->querySingle("SELECT * FROM users WHERE id = :id", [':id' => $user_id]);
                if (!$userRow || !password_verify($currentPassword, $userRow['password'])) {
                    sendJsonResponse(['error' => 'Неверный текущий пароль']);
                }
                
                $updates = [];
                $params = [':id' => $user_id];
                
                // Смена email
                if ($newEmail !== '') {
                    $emailValidation = Security::validateEmail($newEmail);
                    if ($emailValidation !== true) sendJsonResponse(['error' => $emailValidation]);
                    
                    $newEmailHash = Encryption::encryptForSearch($newEmail);
                    // Проверяем уникальность
                    $existing = $dbManager->queryValue("SELECT id FROM users WHERE email_hash = :h AND id != :id", [':h' => $newEmailHash, ':id' => $user_id]);
                    if ($existing) sendJsonResponse(['error' => 'Этот email уже используется другим аккаунтом']);
                    
                    $updates[] = "email_encrypted = :ee, email_hash = :eh";
                    $params[':ee'] = Encryption::encrypt($newEmail);
                    $params[':eh'] = $newEmailHash;
                }
                
                // Смена пароля
                if ($newPassword !== '') {
                    $passwordValidation = Security::validatePassword($newPassword);
                    if ($passwordValidation !== true) sendJsonResponse(['error' => $passwordValidation]);
                    if ($newPassword === $currentPassword) sendJsonResponse(['error' => 'Новый пароль должен отличаться от текущего']);
                    
                    $updates[] = "password = :np";
                    $params[':np'] = password_hash($newPassword, PASSWORD_BCRYPT, ['cost' => BCRYPT_COST]);
                }
                
                if (empty($updates)) sendJsonResponse(['error' => 'Нет данных для обновления']);
                
                $dbManager->execute("UPDATE users SET " . implode(', ', $updates) . " WHERE id = :id", $params);
                Cache::clear('user_' . $user_id);
                sendJsonResponse(['success' => true, 'message' => 'Настройки успешно обновлены']);
                break;
                
            // === ЗАГРУЗКА АВАТАРА ===
            case 'upload_avatar':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                
                if (!isset($_FILES['avatar'])) sendJsonResponse(['error' => 'Файл не загружен']);
                
                if (!Security::checkRateLimit('avatar', $user_id, 5, 3600)) {
                    sendJsonResponse(['error' => 'Слишком много загрузок аватара. Попробуйте позже.']);
                }
                
                $upload = Security::processUpload($_FILES['avatar'], 'avatar');
                if (isset($upload['error'])) sendJsonResponse(['error' => $upload['error']]);
                
                // Удаляем старый аватар
                $oldAvatar = $dbManager->queryValue("SELECT avatar FROM users WHERE id = :id", [':id' => $user_id]);
                if ($oldAvatar && file_exists(AVATAR_DIR . $oldAvatar)) {
                    unlink(AVATAR_DIR . $oldAvatar);
                }
                
                $dbManager->execute("UPDATE users SET avatar = :av WHERE id = :id", [':av' => $upload['filename'], ':id' => $user_id]);
                Cache::clear('user_' . $user_id);
                
                sendJsonResponse(['success' => true, 'avatar' => AVATAR_DIR . $upload['filename']]);
                break;
                
            // === УДАЛЕНИЕ АВАТАРА ===
            case 'delete_avatar':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                
                $oldAvatar = $dbManager->queryValue("SELECT avatar FROM users WHERE id = :id", [':id' => $user_id]);
                if ($oldAvatar && file_exists(AVATAR_DIR . $oldAvatar)) unlink(AVATAR_DIR . $oldAvatar);
                
                $dbManager->execute("UPDATE users SET avatar = NULL WHERE id = :id", [':id' => $user_id]);
                Cache::clear('user_' . $user_id);
                sendJsonResponse(['success' => true]);
                break;
                
            case 'search_users':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $query = trim($_POST['query'] ?? '');
                if (mb_strlen($query) < 2) sendJsonResponse(['success' => true, 'users' => []]);
                $users = $dbManager->searchUsers($query, $user_id, 20);
                sendJsonResponse(['success' => true, 'users' => array_map(fn($u) => ['id' => $u['id'], 'username' => $u['username'], 'avatar' => $u['avatar'], 'status' => $u['status']], $users)]);
                break;
                
            case 'send_friend_request':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $to_user = (int)$_POST['user_id'];
                if ($to_user == $user_id) sendJsonResponse(['error' => 'Нельзя отправить запрос самому себе']);
                $stmt = $dbManager->prepare("SELECT id FROM users WHERE id = :id");
                $stmt->bindValue(':id', $to_user);
                if (!$stmt->execute()->fetchArray()) sendJsonResponse(['error' => 'Пользователь не найден']);
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("INSERT OR IGNORE INTO friend_requests (from_user, to_user) VALUES (:f, :t)");
                    $stmt->bindValue(':f', $user_id);
                    $stmt->bindValue(':t', $to_user);
                    $stmt->execute();
                    if ($db->changes() > 0) { $dbManager->commitTransaction(); Cache::clear('friend_requests'); sendJsonResponse(['success' => true]); }
                    else { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Запрос уже отправлен']); }
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка отправки запроса']); }
                break;
                
            case 'get_friend_requests':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $requests = Cache::remember('friend_requests_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("SELECT fr.*, u.username_encrypted, u.avatar FROM friend_requests fr JOIN users u ON u.id = fr.from_user WHERE fr.to_user = :uid AND fr.status = 'pending' ORDER BY fr.created_at DESC");
                    $stmt->bindValue(':uid', $user_id);
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
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $invites = Cache::remember('group_invites_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("SELECT gi.*, g.name_encrypted as gne, u.username_encrypted as une FROM group_invites gi JOIN groups g ON g.id = gi.group_id JOIN users u ON u.id = gi.from_user WHERE gi.to_user = :uid AND gi.status = 'pending' ORDER BY gi.created_at DESC");
                    $stmt->bindValue(':uid', $user_id);
                    $result = $stmt->execute();
                    $invites = [];
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $row['group_name'] = Encryption::decrypt($row['gne']);
                        $row['inviter_name'] = Encryption::decrypt($row['une']);
                        unset($row['gne'], $row['une']);
                        $invites[] = $row;
                    }
                    return $invites;
                }, 30);
                sendJsonResponse(['success' => true, 'invites' => $invites]);
                break;
                
            case 'respond_friend_request':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $request_id = (int)$_POST['request_id'];
                $accept = $_POST['accept'] === 'true';
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("UPDATE friend_requests SET status = :s, updated_at = CURRENT_TIMESTAMP WHERE id = :id AND to_user = :uid AND status = 'pending'");
                    $stmt->bindValue(':s', $accept ? 'accepted' : 'rejected');
                    $stmt->bindValue(':id', $request_id);
                    $stmt->bindValue(':uid', $user_id);
                    $stmt->execute();
                    if ($db->changes() > 0) { $dbManager->commitTransaction(); Cache::clear('friend_requests'); Cache::clear('friends_' . $user_id); sendJsonResponse(['success' => true]); }
                    else { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Запрос не найден']); }
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'respond_group_invite':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $invite_id = (int)$_POST['invite_id'];
                $accept = $_POST['accept'] === 'true';
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("SELECT * FROM group_invites WHERE id = :id AND to_user = :uid AND status = 'pending'");
                    $stmt->bindValue(':id', $invite_id);
                    $stmt->bindValue(':uid', $user_id);
                    $invite = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                    if (!$invite) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Приглашение не найдено']); }
                    $stmt = $dbManager->prepare("UPDATE group_invites SET status = :s WHERE id = :id");
                    $stmt->bindValue(':s', $accept ? 'accepted' : 'rejected');
                    $stmt->bindValue(':id', $invite_id);
                    $stmt->execute();
                    if ($accept) {
                        $stmt = $dbManager->prepare("INSERT OR IGNORE INTO group_members (group_id, user_id) VALUES (:g, :u)");
                        $stmt->bindValue(':g', $invite['group_id']);
                        $stmt->bindValue(':u', $user_id);
                        $stmt->execute();
                    }
                    $dbManager->commitTransaction();
                    Cache::clear('group_invites');
                    Cache::clear('groups_' . $user_id);
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'get_friends':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $friends = Cache::remember('friends_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("SELECT u.* FROM friend_requests fr JOIN users u ON (u.id = CASE WHEN fr.from_user = :uid THEN fr.to_user ELSE fr.from_user END) WHERE (fr.from_user = :uid OR fr.to_user = :uid) AND fr.status = 'accepted'");
                    $stmt->bindValue(':uid', $user_id);
                    $result = $stmt->execute();
                    $friends = [];
                    while ($f = $result->fetchArray(SQLITE3_ASSOC)) {
                        $f['username'] = Encryption::decrypt($f['username_encrypted']);
                        if ($f['email_encrypted']) $f['email'] = Encryption::decrypt($f['email_encrypted']);
                        unset($f['password'], $f['username_encrypted'], $f['email_encrypted'], $f['username_hash'], $f['email_hash'], $f['username_prefix'], $f['ip_address_encrypted']);
                        $friends[] = $f;
                    }
                    return $friends;
                }, 60);
                sendJsonResponse(['success' => true, 'friends' => $friends]);
                break;
                
            case 'create_group':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $name = trim($_POST['name'] ?? '');
                $description = trim($_POST['description'] ?? '');
                if (mb_strlen($name) < 3 || mb_strlen($name) > MAX_GROUP_NAME_LENGTH) sendJsonResponse(['error' => 'Название группы: от 3 до ' . MAX_GROUP_NAME_LENGTH . ' символов']);
                if (mb_strlen($description) > MAX_GROUP_DESC_LENGTH) sendJsonResponse(['error' => 'Описание слишком длинное (максимум ' . MAX_GROUP_DESC_LENGTH . ' символов)']);
                if (!preg_match('/^[a-zA-Z0-9а-яА-ЯёЁ\s\-_]+$/u', $name)) sendJsonResponse(['error' => 'Название содержит недопустимые символы']);
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("INSERT INTO groups (name_encrypted, name_hash, name_prefix, description_encrypted, creator_id) VALUES (:ne, :nh, :np, :de, :c)");
                    $stmt->bindValue(':ne', Encryption::encrypt($name));
                    $stmt->bindValue(':nh', Encryption::encryptForSearch($name));
                    $stmt->bindValue(':np', Encryption::encryptForPrefix($name));
                    $stmt->bindValue(':de', $description ? Encryption::encrypt($description) : null);
                    $stmt->bindValue(':c', $user_id);
                    $stmt->execute();
                    $group_id = $db->lastInsertRowID();
                    $stmt = $dbManager->prepare("INSERT INTO group_members (group_id, user_id, role) VALUES (:g, :u, 'admin')");
                    $stmt->bindValue(':g', $group_id);
                    $stmt->bindValue(':u', $user_id);
                    $stmt->execute();
                    $dbManager->commitTransaction();
                    Cache::clear('groups_' . $user_id);
                    sendJsonResponse(['success' => true, 'group_id' => $group_id]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Группа с таким названием уже существует']); }
                break;
                
            case 'invite_to_group':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $group_id = (int)$_POST['group_id'];
                $to_user = (int)$_POST['user_id'];
                if ($to_user == $user_id) sendJsonResponse(['error' => 'Нельзя пригласить себя']);
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("SELECT role FROM group_members WHERE group_id = :g AND user_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id);
                    $member = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                    if (!$member) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Вы не состоите в этой группе']); }
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :g AND user_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $to_user);
                    if ($stmt->execute()->fetchArray()) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Пользователь уже в группе']); }
                    $stmt = $dbManager->prepare("INSERT OR IGNORE INTO group_invites (group_id, from_user, to_user) VALUES (:g, :f, :t)");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':f', $user_id); $stmt->bindValue(':t', $to_user);
                    $stmt->execute();
                    $dbManager->commitTransaction();
                    Cache::clear('group_invites_' . $to_user);
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'get_groups':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $groups = Cache::remember('groups_' . $user_id, function() use ($dbManager, $user_id) {
                    $stmt = $dbManager->prepare("SELECT g.*, (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count, gm.role as user_role FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = :uid");
                    $stmt->bindValue(':uid', $user_id);
                    $result = $stmt->execute();
                    $groups = [];
                    while ($group = $result->fetchArray(SQLITE3_ASSOC)) {
                        $group['name'] = Encryption::decrypt($group['name_encrypted']);
                        if ($group['description_encrypted']) $group['description'] = Encryption::decrypt($group['description_encrypted']);
                        unset($group['name_encrypted'], $group['description_encrypted'], $group['name_hash'], $group['name_prefix']);
                        $groups[] = $group;
                    }
                    return $groups;
                }, 60);
                sendJsonResponse(['success' => true, 'groups' => $groups]);
                break;
                
            case 'get_group_members':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $group_id = (int)$_POST['group_id'];
                $members = Cache::remember('group_members_' . $group_id, function() use ($dbManager, $group_id) {
                    $stmt = $dbManager->prepare("SELECT u.id, u.username_encrypted, u.avatar, u.status, gm.role FROM group_members gm JOIN users u ON u.id = gm.user_id WHERE gm.group_id = :gid");
                    $stmt->bindValue(':gid', $group_id);
                    $result = $stmt->execute();
                    $members = [];
                    while ($m = $result->fetchArray(SQLITE3_ASSOC)) {
                        $m['username'] = Encryption::decrypt($m['username_encrypted']);
                        unset($m['username_encrypted']);
                        $members[] = $m;
                    }
                    return $members;
                }, 30);
                sendJsonResponse(['success' => true, 'members' => $members]);
                break;
                
            case 'leave_group':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $group_id = (int)$_POST['group_id'];
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("SELECT creator_id FROM groups WHERE id = :g");
                    $stmt->bindValue(':g', $group_id);
                    $group = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                    if ($group && $group['creator_id'] == $user_id) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Создатель не может покинуть группу. Удалите группу или передайте права.']); }
                    $stmt = $dbManager->prepare("DELETE FROM group_members WHERE group_id = :g AND user_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id);
                    $stmt->execute();
                    $dbManager->commitTransaction();
                    Cache::clear('groups_' . $user_id);
                    Cache::clear('group_members_' . $group_id);
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'delete_group':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $group_id = (int)$_POST['group_id'];
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("DELETE FROM groups WHERE id = :g AND creator_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id);
                    $stmt->execute();
                    if ($db->changes() > 0) { $dbManager->commitTransaction(); Cache::clear('groups_' . $user_id); Cache::clear('group_members_' . $group_id); sendJsonResponse(['success' => true]); }
                    else { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Нет прав на удаление']); }
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'delete_chat':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $chat_with = isset($_POST['chat_with']) ? (int)$_POST['chat_with'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                if (!$chat_with && !$group_id) sendJsonResponse(['error' => 'Не указан чат']);
                $dbManager->beginTransaction();
                try {
                    if ($chat_with) {
                        $stmt = $dbManager->prepare("DELETE FROM friend_requests WHERE ((from_user = :u AND to_user = :c) OR (from_user = :c AND to_user = :u)) AND status = 'accepted'");
                        $stmt->bindValue(':u', $user_id); $stmt->bindValue(':c', $chat_with); $stmt->execute();
                        
                        $stmt = $dbManager->prepare("SELECT file_path FROM messages WHERE (sender_id = :u AND receiver_id = :c) OR (sender_id = :c AND receiver_id = :u)");
                        $stmt->bindValue(':u', $user_id); $stmt->bindValue(':c', $chat_with);
                        $result = $stmt->execute();
                        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                            if ($row['file_path'] && file_exists(UPLOAD_DIR . $row['file_path'])) unlink(UPLOAD_DIR . $row['file_path']);
                        }
                        
                        $stmt = $dbManager->prepare("DELETE FROM messages WHERE (sender_id = :u AND receiver_id = :c) OR (sender_id = :c AND receiver_id = :u)");
                        $stmt->bindValue(':u', $user_id); $stmt->bindValue(':c', $chat_with); $stmt->execute();
                    } else if ($group_id) {
                        $stmt = $dbManager->prepare("SELECT creator_id FROM groups WHERE id = :g");
                        $stmt->bindValue(':g', $group_id);
                        $group = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                        if ($group && $group['creator_id'] != $user_id) {
                            $stmt = $dbManager->prepare("DELETE FROM group_members WHERE group_id = :g AND user_id = :u");
                            $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id); $stmt->execute();
                        } else {
                            $stmt = $dbManager->prepare("DELETE FROM groups WHERE id = :g");
                            $stmt->bindValue(':g', $group_id); $stmt->execute();
                        }
                    }
                    $dbManager->commitTransaction();
                    Cache::clear('friends_' . $user_id);
                    if ($chat_with) Cache::clear('friends_' . $chat_with);
                    Cache::clear('groups_' . $user_id);
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); error_log("delete_chat error: " . $e->getMessage()); sendJsonResponse(['error' => 'Ошибка удаления']); }
                break;
                
            case 'send_message':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                
                $message = $_POST['message'] ?? '';
                $type = Security::sanitizeInput($_POST['type'] ?? 'text');
                $receiver_id = isset($_POST['receiver_id']) ? (int)$_POST['receiver_id'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                $reply_to = isset($_POST['reply_to']) ? (int)$_POST['reply_to'] : null;
                
                if (!$receiver_id && !$group_id) sendJsonResponse(['error' => 'Не указан получатель']);
                
                // Валидация длины сообщения
                $msgValidation = Security::validateMessage($message);
                if ($msgValidation !== true) sendJsonResponse(['error' => $msgValidation]);
                
                // Антиспам проверка
                $spamCheck = SpamDetector::check($user_id, $message);
                if ($spamCheck['blocked']) sendJsonResponse(['error' => $spamCheck['reason']]);
                
                if ($group_id) {
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :g AND user_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id);
                    if (!$stmt->execute()->fetchArray()) sendJsonResponse(['error' => 'Вы не состоите в этой группе']);
                }
                
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("INSERT INTO messages (sender_id, receiver_id, group_id, message_encrypted, message_hash, message_prefix, type, reply_to, ip_address_encrypted) VALUES (:s, :r, :g, :me, :mh, :mp, :t, :rep, :ip)");
                    $stmt->bindValue(':s', $user_id);
                    $stmt->bindValue(':r', $receiver_id);
                    $stmt->bindValue(':g', $group_id);
                    $stmt->bindValue(':me', Encryption::encrypt($message));
                    $stmt->bindValue(':mh', $message ? Encryption::encryptForSearch($message) : null);
                    $stmt->bindValue(':mp', $message ? Encryption::encryptForPrefix($message) : null);
                    $stmt->bindValue(':t', $type);
                    $stmt->bindValue(':rep', $reply_to);
                    $stmt->bindValue(':ip', Encryption::encrypt($clientIP));
                    $stmt->execute();
                    $message_id = $db->lastInsertRowID();
                    $dbManager->commitTransaction();
                    
                    $readCount = $dbManager->addReadReceipt($message_id, $user_id);
                    $stmt = $dbManager->prepare("SELECT m.*, u.username_encrypted, u.avatar FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = :id");
                    $stmt->bindValue(':id', $message_id);
                    $newMessage = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                    if ($newMessage) {
                        $newMessage['message'] = Encryption::decrypt($newMessage['message_encrypted']);
                        $newMessage['username'] = Encryption::decrypt($newMessage['username_encrypted']);
                        $newMessage['read_count'] = $readCount;
                        unset($newMessage['message_encrypted'], $newMessage['message_hash'], $newMessage['message_prefix'], $newMessage['username_encrypted'], $newMessage['ip_address_encrypted']);
                    }
                    Cache::clear('messages_' . ($receiver_id ?: $group_id));
                    sendJsonResponse(['success' => true, 'message' => $newMessage]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); error_log("Send message error: " . $e->getMessage()); sendJsonResponse(['error' => 'Ошибка отправки']); }
                break;
                
            case 'upload_file':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                if (!Security::checkRateLimit('file', $user_id, RATE_LIMIT_FILE_UPLOADS, 60)) sendJsonResponse(['error' => 'Слишком много загрузок. Подождите минуту.']);
                if (!isset($_FILES['file'])) sendJsonResponse(['error' => 'Файл не загружен']);
                $file = $_FILES['file'];
                $receiver_id = isset($_POST['receiver_id']) ? (int)$_POST['receiver_id'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                if (!$receiver_id && !$group_id) sendJsonResponse(['error' => 'Не указан получатель']);
                $type = strpos($file['type'], 'image/') === 0 ? 'image' : 'file';
                $upload = Security::processUpload($file, $type);
                if (isset($upload['error'])) sendJsonResponse(['error' => $upload['error']]);
                if ($group_id) {
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :g AND user_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id);
                    if (!$stmt->execute()->fetchArray()) { unlink($upload['path']); sendJsonResponse(['error' => 'Вы не состоите в этой группе']); }
                }
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("INSERT INTO messages (sender_id, receiver_id, group_id, type, file_name, file_path, file_size, file_type, ip_address_encrypted) VALUES (:s, :r, :g, :t, :fn, :fp, :fs, :ft, :ip)");
                    $stmt->bindValue(':s', $user_id); $stmt->bindValue(':r', $receiver_id); $stmt->bindValue(':g', $group_id);
                    $stmt->bindValue(':t', $type); $stmt->bindValue(':fn', $upload['original_name']); $stmt->bindValue(':fp', $upload['filename']);
                    $stmt->bindValue(':fs', $upload['size']); $stmt->bindValue(':ft', $upload['mime_type']); $stmt->bindValue(':ip', Encryption::encrypt($clientIP));
                    $stmt->execute();
                    $message_id = $db->lastInsertRowID();
                    $dbManager->commitTransaction();
                    $readCount = $dbManager->addReadReceipt($message_id, $user_id);
                    $stmt = $dbManager->prepare("SELECT m.*, u.username_encrypted, u.avatar FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.id = :id");
                    $stmt->bindValue(':id', $message_id);
                    $newMessage = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                    $newMessage['username'] = Encryption::decrypt($newMessage['username_encrypted']);
                    $newMessage['read_count'] = $readCount;
                    unset($newMessage['username_encrypted'], $newMessage['ip_address_encrypted']);
                    Cache::clear('messages_' . ($receiver_id ?: $group_id));
                    sendJsonResponse(['success' => true, 'message' => $newMessage, 'file_url' => UPLOAD_DIR . $upload['filename']]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); unlink($upload['path']); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'get_messages':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $chat_with = isset($_POST['chat_with']) ? (int)$_POST['chat_with'] : null;
                $group_id = isset($_POST['group_id']) ? (int)$_POST['group_id'] : null;
                $before_id = isset($_POST['before_id']) ? (int)$_POST['before_id'] : null;
                $limit = 50;
                if (!$chat_with && !$group_id) sendJsonResponse(['error' => 'Не указан чат']);
                
                if ($group_id) {
                    $stmt = $dbManager->prepare("SELECT 1 FROM group_members WHERE group_id = :g AND user_id = :u");
                    $stmt->bindValue(':g', $group_id); $stmt->bindValue(':u', $user_id);
                    if (!$stmt->execute()->fetchArray()) sendJsonResponse(['error' => 'Нет доступа к группе']);
                    $query = "SELECT m.*, u.username_encrypted, u.avatar FROM messages m JOIN users u ON u.id = m.sender_id WHERE m.group_id = :cid";
                    if ($before_id) $query .= " AND m.id < :bid";
                    $query .= " ORDER BY m.sent_at DESC LIMIT :lim";
                    $stmt = $dbManager->prepare($query);
                    $stmt->bindValue(':cid', $group_id);
                } else {
                    $query = "SELECT m.*, u.username_encrypted, u.avatar FROM messages m JOIN users u ON u.id = m.sender_id WHERE ((m.sender_id = :uid AND m.receiver_id = :cid) OR (m.sender_id = :cid AND m.receiver_id = :uid))";
                    if ($before_id) $query .= " AND m.id < :bid";
                    $query .= " ORDER BY m.sent_at DESC LIMIT :lim";
                    $stmt = $dbManager->prepare($query);
                    $stmt->bindValue(':cid', $chat_with);
                }
                $stmt->bindValue(':uid', $user_id);
                $stmt->bindValue(':lim', $limit);
                if ($before_id) $stmt->bindValue(':bid', $before_id);
                
                $result = $stmt->execute();
                $messages = [];
                $messageIds = [];
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) $messageIds[] = $row['id'];
                $readCounts = $group_id ? $dbManager->getGroupReadCounts($group_id, $messageIds) : [];
                $result->reset();
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    if ($row['sender_id'] != $user_id) $dbManager->addReadReceipt($row['id'], $user_id);
                    $row['read_count'] = $group_id ? ($readCounts[$row['id']] ?? 0) : 1;
                    $row['message'] = Encryption::decrypt($row['message_encrypted'] ?? '');
                    $row['username'] = Encryption::decrypt($row['username_encrypted']);
                    unset($row['message_encrypted'], $row['message_hash'], $row['message_prefix'], $row['username_encrypted'], $row['ip_address_encrypted']);
                    $messages[] = $row;
                }
                sendJsonResponse(['success' => true, 'messages' => array_reverse($messages)]);
                break;
                
            case 'add_reaction':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $message_id = (int)$_POST['message_id'];
                $reaction = Security::sanitizeInput($_POST['reaction'] ?? '');
                if (mb_strlen($reaction) > 10) sendJsonResponse(['error' => 'Реакция слишком длинная']);
                $stmt = $dbManager->prepare("SELECT 1 FROM messages m LEFT JOIN group_members gm ON m.group_id = gm.group_id WHERE m.id = :mid AND ((m.receiver_id = :uid OR m.sender_id = :uid) OR gm.user_id = :uid)");
                $stmt->bindValue(':mid', $message_id); $stmt->bindValue(':uid', $user_id);
                if (!$stmt->execute()->fetchArray()) sendJsonResponse(['error' => 'Нет доступа к сообщению']);
                $dbManager->beginTransaction();
                try {
                    if ($reaction) {
                        $stmt = $dbManager->prepare("INSERT OR REPLACE INTO reactions (message_id, user_id, reaction) VALUES (:m, :u, :r)");
                        $stmt->bindValue(':r', $reaction);
                    } else {
                        $stmt = $dbManager->prepare("DELETE FROM reactions WHERE message_id = :m AND user_id = :u");
                    }
                    $stmt->bindValue(':m', $message_id); $stmt->bindValue(':u', $user_id); $stmt->execute();
                    $dbManager->commitTransaction();
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'get_reactions':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $message_id = (int)$_POST['message_id'];
                $stmt = $dbManager->prepare("SELECT r.*, u.username_encrypted FROM reactions r JOIN users u ON u.id = r.user_id WHERE r.message_id = :mid");
                $stmt->bindValue(':mid', $message_id);
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
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $message_id = (int)$_POST['message_id'];
                $for_everyone = isset($_POST['for_everyone']) && $_POST['for_everyone'] === 'true';
                $dbManager->beginTransaction();
                try {
                    $stmt = $dbManager->prepare("SELECT m.*, g.creator_id as group_creator FROM messages m LEFT JOIN groups g ON m.group_id = g.id WHERE m.id = :mid");
                    $stmt->bindValue(':mid', $message_id);
                    $msg = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                    if (!$msg) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Сообщение не найдено']); }
                    $canDelete = ($msg['sender_id'] == $user_id) || ($msg['group_id'] && $msg['group_creator'] == $user_id);
                    if (!$canDelete) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Нет прав на удаление']); }
                    if ($msg['file_path'] && file_exists(UPLOAD_DIR . $msg['file_path'])) unlink(UPLOAD_DIR . $msg['file_path']);
                    $stmt = $dbManager->prepare("DELETE FROM messages WHERE id = :mid");
                    $stmt->bindValue(':mid', $message_id); $stmt->execute();
                    $dbManager->commitTransaction();
                    Cache::clear('messages_' . ($msg['receiver_id'] ?: $msg['group_id']));
                    sendJsonResponse(['success' => true]);
                } catch (Exception $e) { $dbManager->rollbackTransaction(); sendJsonResponse(['error' => 'Ошибка']); }
                break;
                
            case 'edit_message':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $message_id = (int)$_POST['message_id'];
                $new_text = $_POST['message'] ?? '';
                $msgValidation = Security::validateMessage($new_text);
                if ($msgValidation !== true) sendJsonResponse(['error' => $msgValidation]);
                $stmt = $dbManager->prepare("SELECT receiver_id, group_id FROM messages WHERE id = :mid AND sender_id = :uid AND datetime(sent_at) > datetime('now', '-5 minutes')");
                $stmt->bindValue(':mid', $message_id); $stmt->bindValue(':uid', $user_id);
                $msg = $stmt->execute()->fetchArray(SQLITE3_ASSOC);
                if ($msg) {
                    $stmt = $dbManager->prepare("UPDATE messages SET message_encrypted = :me, message_hash = :mh, message_prefix = :mp, is_edited = 1 WHERE id = :mid");
                    $stmt->bindValue(':me', Encryption::encrypt($new_text));
                    $stmt->bindValue(':mh', Encryption::encryptForSearch($new_text));
                    $stmt->bindValue(':mp', Encryption::encryptForPrefix($new_text));
                    $stmt->bindValue(':mid', $message_id);
                    $stmt->execute();
                    Cache::clear('messages_' . ($msg['receiver_id'] ?: $msg['group_id']));
                    sendJsonResponse(['success' => true]);
                } else { sendJsonResponse(['error' => 'Нельзя редактировать (прошло более 5 минут или нет прав)']); }
                break;
                
            case 'change_theme':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $theme = $_POST['theme'] === 'dark' ? 'dark' : 'light';
                $stmt = $dbManager->prepare("UPDATE users SET theme = :t WHERE id = :id");
                $stmt->bindValue(':t', $theme); $stmt->bindValue(':id', $user_id); $stmt->execute();
                $_SESSION['theme'] = $theme;
                sendJsonResponse(['success' => true]);
                break;
                
            case 'get_online_status':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $user_ids = isset($_POST['user_ids']) ? json_decode($_POST['user_ids'], true) : [];
                if (empty($user_ids)) sendJsonResponse(['success' => true, 'statuses' => []]);
                $user_ids = array_map('intval', array_filter($user_ids, 'is_numeric'));
                if (empty($user_ids)) sendJsonResponse(['success' => true, 'statuses' => []]);
                $placeholders = implode(',', array_fill(0, count($user_ids), '?'));
                $stmt = $dbManager->prepare("SELECT id, status, last_seen FROM users WHERE id IN ($placeholders)");
                foreach ($user_ids as $i => $id) $stmt->bindValue($i + 1, $id);
                $result = $stmt->execute();
                $statuses = [];
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) $statuses[$row['id']] = ['status' => $row['status'], 'last_seen' => $row['last_seen']];
                sendJsonResponse(['success' => true, 'statuses' => $statuses]);
                break;
                
            case 'logout':
                if ($user_id) {
                    if (isset($_SESSION['session_token'])) {
                        $stmt = $dbManager->prepare("DELETE FROM user_sessions WHERE session_token = :t");
                        $stmt->bindValue(':t', $_SESSION['session_token']); $stmt->execute();
                    }
                    $stmt = $dbManager->prepare("UPDATE users SET status = 'offline', last_seen = CURRENT_TIMESTAMP WHERE id = :id");
                    $stmt->bindValue(':id', $user_id); $stmt->execute();
                }
                $_SESSION = [];
                session_destroy();
                sendJsonResponse(['success' => true]);
                break;
                
            // === ПОЛУЧИТЬ ДАННЫЕ АККАУНТА ===
            case 'get_account_info':
                if (!$user_id) sendJsonResponse(['error' => 'Не авторизован']);
                $userRow = $dbManager->querySingle("SELECT id, username_encrypted, email_encrypted, avatar, status, theme, created_at FROM users WHERE id = :id", [':id' => $user_id]);
                if (!$userRow) sendJsonResponse(['error' => 'Пользователь не найден']);
                $info = [
                    'id' => $userRow['id'],
                    'username' => Encryption::decrypt($userRow['username_encrypted']),
                    'email' => $userRow['email_encrypted'] ? Encryption::decrypt($userRow['email_encrypted']) : '',
                    'avatar' => $userRow['avatar'],
                    'status' => $userRow['status'],
                    'theme' => $userRow['theme'],
                    'created_at' => $userRow['created_at'],
                    'limits' => [
                        'max_message_length' => MAX_MESSAGE_LENGTH,
                        'min_password_length' => MIN_PASSWORD_LENGTH,
                        'max_password_length' => MAX_PASSWORD_LENGTH,
                        'min_username_length' => MIN_USERNAME_LENGTH,
                        'max_username_length' => MAX_USERNAME_LENGTH,
                        'max_email_length' => MAX_EMAIL_LENGTH,
                    ]
                ];
                sendJsonResponse(['success' => true, 'account' => $info]);
                break;
                
            default:
                sendJsonResponse(['error' => 'Неизвестное действие']);
        }
    } catch (Exception $e) {
        error_log("Error in action $action: " . $e->getMessage());
        sendJsonResponse(['error' => 'Внутренняя ошибка сервера'], 500);
    }
}

if (isset($_SESSION['user_id'])) {
    if (isset($_SESSION['user_agent']) && $_SESSION['user_agent'] !== ($_SERVER['HTTP_USER_AGENT'] ?? '')) {
        session_destroy();
        showLoginPage();
        exit;
    }
    if (isset($_SESSION['session_token'])) {
        $stmt = $dbManager->prepare("SELECT 1 FROM user_sessions WHERE session_token = :t AND expires_at > CURRENT_TIMESTAMP");
        $stmt->bindValue(':t', $_SESSION['session_token']);
        if (!$stmt->execute()->fetchArray()) { session_destroy(); showLoginPage(); exit; }
    } else { session_destroy(); showLoginPage(); exit; }
}

if (!isset($_SESSION['user_id'])) { showLoginPage(); exit; }

$user_id = $_SESSION['user_id'];
$stmt = $dbManager->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindValue(':id', $user_id);
$current_user = $stmt->execute()->fetchArray(SQLITE3_ASSOC);

if (!$current_user) { session_destroy(); showLoginPage(); exit; }

$current_user['username'] = Encryption::decrypt($current_user['username_encrypted']);
if ($current_user['email_encrypted']) $current_user['email'] = Encryption::decrypt($current_user['email_encrypted']);
unset($current_user['username_encrypted'], $current_user['email_encrypted'], $current_user['username_hash'], $current_user['email_hash'], $current_user['username_prefix'], $current_user['ip_address_encrypted']);

$stmt = $dbManager->prepare("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = :id");
$stmt->bindValue(':id', $user_id);
$stmt->execute();

$theme = $current_user['theme'] ?? 'light';
if (isset($_SESSION['theme'])) $theme = $_SESSION['theme'];

function showLoginPage() {
    $csrf_token = Security::generateCSRFToken();
    $turnstile_site_key = TURNSTILE_SITE_KEY;
    $min_pw = MIN_PASSWORD_LENGTH;
    $max_pw = MAX_PASSWORD_LENGTH;
    $min_un = MIN_USERNAME_LENGTH;
    $max_un = MAX_USERNAME_LENGTH;
    $max_em = MAX_EMAIL_LENGTH;
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0">
    <meta name="theme-color" content="#0b1120">
    <title>liveto.chat — Безопасный мессенджер</title>
    <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#0b1120 0%,#1a1f35 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
        .auth-container{background:rgba(255,255,255,.05);backdrop-filter:blur(10px);border-radius:32px;padding:32px 24px;width:100%;max-width:440px;box-shadow:0 25px 50px -12px rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1);animation:slideUp .5s ease}
        @keyframes slideUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
        @media(max-width:480px){.auth-container{padding:24px 20px;border-radius:28px}}
        .auth-header{text-align:center;margin-bottom:28px}
        .auth-header h1{font-size:clamp(2rem,8vw,2.5rem);background:linear-gradient(135deg,#60a5fa 0%,#a78bfa 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px;letter-spacing:-.5px}
        .auth-header p{color:#94a3b8;font-size:clamp(.9rem,4vw,1rem)}
        .tab-container{display:flex;gap:8px;margin-bottom:28px;background:rgba(255,255,255,.03);padding:6px;border-radius:20px;border:1px solid rgba(255,255,255,.05)}
        .tab{flex:1;padding:14px 8px;text-align:center;border:none;background:transparent;border-radius:14px;font-weight:600;cursor:pointer;transition:all .3s;color:#94a3b8;font-size:.95rem;touch-action:manipulation}
        .tab.active{background:linear-gradient(135deg,#3b82f6 0%,#8b5cf6 100%);color:#fff;box-shadow:0 4px 12px rgba(59,130,246,.3)}
        .auth-form{display:none}.auth-form.active{display:block;animation:fadeIn .3s ease}
        @keyframes fadeIn{from{opacity:0}to{opacity:1}}
        .form-group{margin-bottom:18px}
        .form-group label{display:block;margin-bottom:8px;color:#e2e8f0;font-weight:500;font-size:.95rem}
        .form-group input{width:100%;padding:16px 18px;border:2px solid rgba(255,255,255,.1);border-radius:20px;font-size:16px;transition:all .3s;background:rgba(255,255,255,.05);color:#fff;-webkit-appearance:none}
        .form-group input::placeholder{color:#64748b}
        .form-group input:focus{outline:none;border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.2);background:rgba(255,255,255,.1)}
        .form-group input.error{border-color:#ef4444}
        .field-hint{font-size:.8rem;color:#64748b;margin-top:5px;padding-left:2px}
        .field-hint.warn{color:#f59e0b}
        .cf-turnstile{margin-bottom:18px;display:flex;justify-content:center;min-height:65px}
        .btn{width:100%;padding:18px;border:none;border-radius:24px;background:linear-gradient(135deg,#3b82f6 0%,#8b5cf6 100%);color:#fff;font-size:1.1rem;font-weight:600;cursor:pointer;transition:all .3s;margin-top:6px;touch-action:manipulation}
        .btn:active{transform:scale(.98)}.btn:disabled{opacity:.5;cursor:not-allowed;transform:none}
        .error-message{color:#ef4444;font-size:.9rem;margin-top:12px;text-align:center;background:rgba(239,68,68,.1);padding:12px;border-radius:16px;border:1px solid rgba(239,68,68,.2)}
        .error-message:empty{display:none}
        .password-strength{height:4px;border-radius:2px;margin-top:8px;transition:all .3s;background:#334155}
        .password-strength-bar{height:100%;border-radius:2px;transition:all .3s;width:0}
        .security-badge{display:flex;align-items:center;justify-content:center;gap:8px;margin-top:20px;color:#64748b;font-size:.8rem}
    </style>
</head>
<body>
<div class="auth-container">
    <div class="auth-header">
        <h1>🔒 liveto.chat</h1>
        <p>Безопасное и приватное общение</p>
    </div>
    <div class="tab-container">
        <button class="tab active" onclick="switchTab('login')">Вход</button>
        <button class="tab" onclick="switchTab('register')">Регистрация</button>
    </div>
    <form id="loginForm" class="auth-form active" onsubmit="handleLogin(event)">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <div class="form-group">
            <label>Логин или Email</label>
            <input type="text" id="loginUsername" placeholder="username или email" required autocomplete="username" maxlength="<?php echo max($max_un, $max_em); ?>">
        </div>
        <div class="form-group">
            <label>Пароль</label>
            <input type="password" id="loginPassword" placeholder="••••••••" required autocomplete="current-password" maxlength="<?php echo $max_pw; ?>">
        </div>
        <div class="cf-turnstile" data-sitekey="<?php echo $turnstile_site_key; ?>" data-callback="onTurnstileSuccess"></div>
        <button type="submit" class="btn" id="loginBtn" disabled>Войти</button>
        <div id="loginError" class="error-message"></div>
    </form>
    <form id="registerForm" class="auth-form" onsubmit="handleRegister(event)">
        <input type="hidden" name="csrf_token" value="<?php echo $csrf_token; ?>">
        <div class="form-group">
            <label>Имя пользователя</label>
            <input type="text" id="regUsername" placeholder="john_doe" required autocomplete="username" minlength="<?php echo $min_un; ?>" maxlength="<?php echo $max_un; ?>" oninput="validateUsername(this)">
            <div class="field-hint" id="usernameHint">От <?php echo $min_un; ?> до <?php echo $max_un; ?> символов: буквы, цифры и _</div>
        </div>
        <div class="form-group">
            <label>Email <span style="color:#64748b">(необязательно)</span></label>
            <input type="email" id="regEmail" placeholder="john@example.com" autocomplete="email" maxlength="<?php echo $max_em; ?>">
        </div>
        <div class="form-group">
            <label>Пароль</label>
            <input type="password" id="regPassword" placeholder="••••••••" required autocomplete="new-password" minlength="<?php echo $min_pw; ?>" maxlength="<?php echo $max_pw; ?>" oninput="checkPasswordStrength(this)">
            <div class="password-strength"><div class="password-strength-bar" id="strengthBar"></div></div>
            <div class="field-hint" id="passwordHint">Минимум <?php echo $min_pw; ?> символов: заглавные, строчные, цифры</div>
        </div>
        <div class="form-group">
            <label>Подтвердите пароль</label>
            <input type="password" id="regConfirmPassword" placeholder="••••••••" required autocomplete="new-password" maxlength="<?php echo $max_pw; ?>" oninput="checkPasswordMatch(this)">
        </div>
        <div class="cf-turnstile" data-sitekey="<?php echo $turnstile_site_key; ?>" data-callback="onTurnstileSuccess"></div>
        <button type="submit" class="btn" id="registerBtn" disabled>Создать аккаунт</button>
        <div id="registerError" class="error-message"></div>
    </form>
    <div class="security-badge">🔒 AES-256-GCM шифрование · End-to-End</div>
</div>
<script>
const csrfToken='<?php echo $csrf_token; ?>';
let turnstileToken='';
const LIMITS={minPw:<?php echo $min_pw;?>,maxPw:<?php echo $max_pw;?>,minUn:<?php echo $min_un;?>,maxUn:<?php echo $max_un;?>,maxEm:<?php echo $max_em;?>};

function onTurnstileSuccess(token){
    turnstileToken=token;
    document.getElementById('loginBtn').disabled=false;
    document.getElementById('registerBtn').disabled=false;
}
function switchTab(tab){
    document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.auth-form').forEach(f=>f.classList.remove('active'));
    if(tab==='login'){document.querySelectorAll('.tab')[0].classList.add('active');document.getElementById('loginForm').classList.add('active');}
    else{document.querySelectorAll('.tab')[1].classList.add('active');document.getElementById('registerForm').classList.add('active');}
}
function validateUsername(input){
    const val=input.value;const hint=document.getElementById('usernameHint');
    if(val.length>0&&(val.length<LIMITS.minUn||val.length>LIMITS.maxUn)){hint.className='field-hint warn';hint.textContent=`Длина: ${val.length}/${LIMITS.maxUn} (нужно от ${LIMITS.minUn})`;}
    else if(val.length>0&&!/^[a-zA-Z0-9_]+$/.test(val)){hint.className='field-hint warn';hint.textContent='Только латинские буквы, цифры и _';}
    else{hint.className='field-hint';hint.textContent=`${val.length}/${LIMITS.maxUn} символов`;}
}
function checkPasswordStrength(input){
    const pw=input.value;const bar=document.getElementById('strengthBar');const hint=document.getElementById('passwordHint');
    let score=0;
    if(pw.length>=LIMITS.minPw)score++;
    if(/[A-Z]/.test(pw))score++;
    if(/[a-z]/.test(pw))score++;
    if(/[0-9]/.test(pw))score++;
    if(/[^A-Za-z0-9]/.test(pw))score++;
    const colors=['#ef4444','#f59e0b','#f59e0b','#10b981','#10b981'];
    const labels=['Очень слабый','Слабый','Средний','Сильный','Очень сильный'];
    bar.style.width=(score*20)+'%';
    bar.style.background=colors[score-1]||'#334155';
    hint.textContent=pw.length>0?(labels[score-1]||''):`Минимум ${LIMITS.minPw} симв.: заглавные, строчные, цифры`;
    hint.className='field-hint'+(score<3&&pw.length>0?' warn':'');
}
function checkPasswordMatch(input){
    const pw=document.getElementById('regPassword').value;
    input.style.borderColor=input.value&&input.value!==pw?'#ef4444':'';
}
async function handleLogin(e){
    e.preventDefault();
    if(!turnstileToken){document.getElementById('loginError').textContent='Подтвердите, что вы не робот';return;}
    const btn=document.getElementById('loginBtn');btn.disabled=true;btn.textContent='Вхожу...';
    const fd=new FormData();
    fd.append('action','login');fd.append('username',document.getElementById('loginUsername').value.trim());
    fd.append('password',document.getElementById('loginPassword').value);fd.append('csrf_token',csrfToken);fd.append('cf-turnstile-response',turnstileToken);
    try{
        const r=await fetch('',{method:'POST',body:fd});const d=await r.json();
        if(d.success){window.location.reload();}
        else{document.getElementById('loginError').textContent=d.error||'Ошибка входа';turnstileToken='';btn.disabled=true;btn.textContent='Войти';if(window.turnstile)turnstile.reset();}
    }catch{document.getElementById('loginError').textContent='Ошибка соединения';btn.disabled=false;btn.textContent='Войти';}
}
async function handleRegister(e){
    e.preventDefault();
    if(!turnstileToken){document.getElementById('registerError').textContent='Подтвердите, что вы не робот';return;}
    const un=document.getElementById('regUsername').value.trim();
    const email=document.getElementById('regEmail').value.trim();
    const pw=document.getElementById('regPassword').value;
    const conf=document.getElementById('regConfirmPassword').value;
    const setErr=msg=>{document.getElementById('registerError').textContent=msg;};
    if(un.length<LIMITS.minUn||un.length>LIMITS.maxUn){setErr(`Имя пользователя: от ${LIMITS.minUn} до ${LIMITS.maxUn} символов`);return;}
    if(!/^[a-zA-Z0-9_]+$/.test(un)){setErr('Имя пользователя: только латинские буквы, цифры и _');return;}
    if(pw.length<LIMITS.minPw){setErr(`Пароль должен быть не менее ${LIMITS.minPw} символов`);return;}
    if(pw.length>LIMITS.maxPw){setErr(`Пароль не должен превышать ${LIMITS.maxPw} символов`);return;}
    if(!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(pw)){setErr('Пароль: нужны заглавные, строчные буквы и цифры');return;}
    if(pw!==conf){setErr('Пароли не совпадают');return;}
    if(email&&email.length>LIMITS.maxEm){setErr(`Email слишком длинный (максимум ${LIMITS.maxEm} символов)`);return;}
    const btn=document.getElementById('registerBtn');btn.disabled=true;btn.textContent='Создаю...';
    const fd=new FormData();
    fd.append('action','register');fd.append('username',un);fd.append('email',email||'');fd.append('password',pw);fd.append('csrf_token',csrfToken);fd.append('cf-turnstile-response',turnstileToken);
    try{
        const r=await fetch('',{method:'POST',body:fd});const d=await r.json();
        if(d.success){alert('✅ Регистрация успешна! Теперь войдите.');switchTab('login');document.getElementById('loginUsername').value=un;turnstileToken='';if(window.turnstile)turnstile.reset();}
        else{setErr(d.error||'Ошибка регистрации');btn.disabled=false;btn.textContent='Создать аккаунт';}
    }catch{setErr('Ошибка соединения');btn.disabled=false;btn.textContent='Создать аккаунт';}
}
</script>
</body>
</html>
<?php exit;
}
?>
<!DOCTYPE html>
<html lang="ru" data-theme="<?php echo $theme; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, viewport-fit=cover">
    <meta name="theme-color" content="#0f172a">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <title>liveto.chat — <?php echo htmlspecialchars($current_user['username']); ?></title>
    <style>
        *{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent}
        :root{
            --bg-primary:#ffffff;--bg-secondary:#f8fafc;--bg-tertiary:#f1f5f9;
            --text-primary:#0f172a;--text-secondary:#475569;--text-tertiary:#64748b;
            --border-color:#e2e8f0;--hover-bg:#f1f5f9;--active-bg:#e2e8f0;
            --shadow:0 10px 40px -15px rgba(0,0,0,0.1);
            --message-own:linear-gradient(135deg,#3b82f6 0%,#8b5cf6 100%);
            --message-other:#f1f5f9;--primary:#3b82f6;--primary-dark:#2563eb;
            --success:#10b981;--danger:#ef4444;--warning:#f59e0b;
            --input-bg:#ffffff;--sidebar-width:320px;--header-height:70px;
        }
        [data-theme="dark"]{
            --bg-primary:#0f172a;--bg-secondary:#1e293b;--bg-tertiary:#334155;
            --text-primary:#f8fafc;--text-secondary:#cbd5e1;--text-tertiary:#94a3b8;
            --border-color:#334155;--hover-bg:#334155;--active-bg:#475569;
            --shadow:0 10px 40px -15px rgba(0,0,0,0.5);
            --message-other:#334155;--input-bg:#1e293b;
        }
        body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#0b1120 0%,#1a1f35 100%);height:100vh;display:flex;align-items:center;justify-content:center}
        .app-container{width:100%;height:100vh;background:var(--bg-primary);display:flex;overflow:hidden;animation:slideIn .5s ease;color:var(--text-primary);position:relative}
        @keyframes slideIn{from{opacity:0;transform:scale(.95)}to{opacity:1;transform:scale(1)}}
        
        /* SIDEBAR */
        .sidebar{width:var(--sidebar-width);background:var(--bg-secondary);border-right:1px solid var(--border-color);display:flex;flex-direction:column;transition:transform .3s ease;position:relative;z-index:10;overflow:hidden}
        @media(max-width:768px){.sidebar{position:absolute;left:0;top:0;bottom:0;transform:translateX(-100%);width:85%;max-width:320px;box-shadow:2px 0 20px rgba(0,0,0,.3)}.sidebar.active{transform:translateX(0)}}
        .sidebar-header{padding:16px 16px 12px;border-bottom:1px solid var(--border-color);flex-shrink:0}
        .user-profile{display:flex;align-items:center;gap:12px;cursor:pointer;border-radius:16px;padding:8px;transition:background .2s;margin:-8px}
        .user-profile:hover{background:var(--hover-bg)}
        .avatar{width:48px;height:48px;border-radius:16px;background:linear-gradient(135deg,var(--primary),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:1.2rem;position:relative;box-shadow:0 4px 12px rgba(59,130,246,.3);flex-shrink:0;overflow:hidden}
        .avatar img{width:100%;height:100%;object-fit:cover;border-radius:16px}
        .avatar.online::after{content:'';position:absolute;bottom:2px;right:2px;width:12px;height:12px;background:var(--success);border:2px solid var(--bg-secondary);border-radius:50%}
        .user-info{flex:1;min-width:0}
        .user-info h4{color:var(--text-primary);font-size:1rem;margin-bottom:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        .user-info p{color:var(--text-tertiary);font-size:.8rem}
        .search-bar{padding:12px 16px;position:relative;flex-shrink:0}
        .search-bar input{width:100%;padding:12px 18px;border:2px solid var(--border-color);border-radius:30px;font-size:16px;transition:all .3s;background:var(--input-bg);color:var(--text-primary);-webkit-appearance:none}
        .search-bar input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(59,130,246,.2)}
        .search-results{position:absolute;top:72px;left:16px;right:16px;background:var(--bg-primary);border-radius:20px;box-shadow:var(--shadow);z-index:100;display:none;max-height:280px;overflow-y:auto;border:1px solid var(--border-color)}
        .search-result-item{display:flex;align-items:center;gap:12px;padding:12px 16px;cursor:pointer;transition:background .2s;border-bottom:1px solid var(--border-color)}
        .search-result-item:last-child{border-bottom:none}
        .search-result-item:hover{background:var(--hover-bg)}
        .tabs{display:flex;padding:0 12px;gap:4px;margin-bottom:8px;flex-shrink:0}
        .tab-btn{flex:1;padding:9px 4px;border:none;background:transparent;border-radius:12px;font-weight:600;color:var(--text-tertiary);cursor:pointer;transition:all .3s;font-size:.85rem;touch-action:manipulation}
        .tab-btn.active{background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff}
        .chat-list{flex:1;overflow-y:auto;padding:0 8px;-webkit-overflow-scrolling:touch}
        .chat-item{display:flex;align-items:center;gap:10px;padding:12px 10px;border-radius:16px;cursor:pointer;transition:all .2s;margin-bottom:3px;background:var(--bg-tertiary);border:1px solid transparent;touch-action:manipulation}
        .chat-item:active{background:var(--active-bg);transform:scale(.98)}
        .chat-item.active{background:linear-gradient(135deg,rgba(59,130,246,.12),rgba(139,92,246,.12));border-color:var(--primary)}
        .chat-avatar{width:46px;height:46px;border-radius:14px;background:linear-gradient(135deg,var(--primary),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:1rem;flex-shrink:0;overflow:hidden}
        .chat-avatar img{width:100%;height:100%;object-fit:cover;border-radius:14px}
        .chat-info{flex:1;min-width:0}
        .chat-name{font-weight:600;color:var(--text-primary);margin-bottom:3px;font-size:.95rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        .chat-last-message{font-size:.8rem;color:var(--text-tertiary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        .chat-actions{display:flex;gap:4px;opacity:0;transition:opacity .2s;flex-shrink:0}
        .chat-item:hover .chat-actions{opacity:1}
        @media(max-width:768px){.chat-actions{opacity:1}}
        .chat-action-btn{width:32px;height:32px;border:none;border-radius:8px;background:var(--bg-primary);color:var(--text-tertiary);cursor:pointer;display:flex;align-items:center;justify-content:center;transition:all .2s;border:1px solid var(--border-color);touch-action:manipulation}
        .chat-action-btn:hover,.chat-action-btn:active{background:var(--danger);color:#fff;border-color:var(--danger)}
        
        /* MAIN */
        .main{flex:1;display:flex;flex-direction:column;background:var(--bg-primary);position:relative;min-width:0}
        .chat-header{padding:14px 18px;border-bottom:1px solid var(--border-color);display:flex;align-items:center;justify-content:space-between;background:var(--bg-secondary);height:var(--header-height);gap:10px;flex-shrink:0}
        .menu-toggle{display:none;width:40px;height:40px;border:none;border-radius:12px;background:var(--bg-tertiary);color:var(--text-primary);cursor:pointer;flex-shrink:0;align-items:center;justify-content:center}
        @media(max-width:768px){.menu-toggle{display:flex}}
        .chat-header-info{display:flex;align-items:center;gap:10px;flex:1;min-width:0}
        .chat-header-avatar{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,var(--primary),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;flex-shrink:0;overflow:hidden}
        .chat-header-avatar img{width:100%;height:100%;object-fit:cover;border-radius:14px}
        .chat-header-text{flex:1;min-width:0}
        .chat-header-text h3{color:var(--text-primary);margin-bottom:2px;font-size:1rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        .chat-header-text p{color:var(--success);font-size:.8rem}
        .chat-header-actions{display:flex;gap:6px;flex-shrink:0}
        .action-btn{width:42px;height:42px;border:none;border-radius:12px;background:var(--bg-tertiary);color:var(--text-primary);cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;border:1px solid var(--border-color);touch-action:manipulation}
        .action-btn:hover,.action-btn:active{background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff;border-color:transparent}
        
        /* MESSAGES */
        .messages-container{flex:1;overflow-y:auto;padding:16px 14px;display:flex;flex-direction:column;gap:10px;background:var(--bg-primary);-webkit-overflow-scrolling:touch}
        .message-wrapper{display:flex;gap:8px;max-width:85%;animation:msgIn .25s ease;position:relative}
        @media(min-width:768px){.message-wrapper{max-width:68%}}
        @keyframes msgIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
        .message-wrapper.own{align-self:flex-end;flex-direction:row-reverse}
        .message-avatar{width:34px;height:34px;border-radius:10px;background:linear-gradient(135deg,var(--primary),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:.85rem;flex-shrink:0;overflow:hidden}
        .message-avatar img{width:100%;height:100%;object-fit:cover;border-radius:10px}
        .message-content{background:var(--message-other);padding:10px 14px;border-radius:18px;border-top-left-radius:4px;box-shadow:0 2px 6px rgba(0,0,0,.05);position:relative;color:var(--text-primary);word-break:break-word}
        .message-wrapper.own .message-content{background:var(--message-own);color:#fff;border-top-left-radius:18px;border-top-right-radius:4px}
        .message-sender{font-weight:600;margin-bottom:3px;font-size:.85rem;color:var(--text-primary)}
        .message-wrapper.own .message-sender{color:rgba(255,255,255,.9)}
        .message-text{line-height:1.5;word-break:break-word;font-size:.9rem;white-space:pre-wrap}
        .message-time{font-size:.65rem;color:var(--text-tertiary);margin-top:4px;text-align:right}
        .message-wrapper.own .message-time{color:rgba(255,255,255,.65)}
        .message-image{max-width:100%;max-height:240px;border-radius:12px;cursor:pointer;transition:transform .2s;display:block}
        .message-image:active{transform:scale(.98)}
        .message-file{display:flex;align-items:center;gap:8px;padding:8px 10px;background:rgba(0,0,0,.07);border-radius:10px;cursor:pointer;transition:background .2s}
        .message-wrapper.own .message-file{background:rgba(255,255,255,.15)}
        .message-reactions{display:flex;gap:4px;flex-wrap:wrap;margin-top:5px}
        .reaction-badge{background:rgba(0,0,0,.08);border-radius:10px;padding:2px 7px;font-size:.75rem;cursor:pointer;display:inline-flex;align-items:center;gap:3px}
        .message-wrapper.own .reaction-badge{background:rgba(255,255,255,.2)}
        
        /* INPUT */
        .message-form{padding:12px 14px;border-top:1px solid var(--border-color);display:flex;gap:8px;align-items:flex-end;background:var(--bg-secondary);position:sticky;bottom:0;flex-shrink:0}
        .char-counter{font-size:.7rem;color:var(--text-tertiary);text-align:right;margin-top:3px;padding-right:4px}
        .char-counter.warn{color:var(--warning)}
        .char-counter.danger{color:var(--danger)}
        .message-input-wrapper{flex:1;position:relative;min-width:0}
        .message-input{width:100%;padding:13px 16px;border:2px solid var(--border-color);border-radius:26px;font-size:16px;resize:none;max-height:100px;font-family:inherit;transition:all .3s;background:var(--input-bg);color:var(--text-primary);-webkit-appearance:none}
        .message-input:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
        .message-actions{display:flex;gap:5px;flex-shrink:0}
        .attach-btn,.emoji-btn,.send-btn{width:46px;height:46px;border:none;border-radius:50%;cursor:pointer;transition:all .2s;display:flex;align-items:center;justify-content:center;touch-action:manipulation;font-size:1.2rem}
        .attach-btn,.emoji-btn{background:var(--bg-tertiary);color:var(--text-primary);border:2px solid var(--border-color)}
        .send-btn{background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff;box-shadow:0 4px 12px rgba(59,130,246,.3)}
        .attach-btn:active,.emoji-btn:active{background:var(--primary);color:#fff}
        .send-btn:active{transform:scale(.95)}
        
        /* EMOJI */
        .emoji-picker{position:fixed;bottom:76px;right:14px;left:14px;background:var(--bg-primary);border:1px solid var(--border-color);border-radius:22px;padding:14px;display:none;grid-template-columns:repeat(6,1fr);gap:6px;max-height:230px;overflow-y:auto;box-shadow:var(--shadow);z-index:1000}
        @media(min-width:480px){.emoji-picker{left:auto;width:330px}}
        .emoji-item{font-size:1.6rem;padding:7px;cursor:pointer;border-radius:10px;text-align:center;transition:background .2s}
        .emoji-item:active{background:var(--hover-bg);transform:scale(1.1)}
        
        /* MODALS */
        .modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.65);z-index:2000;align-items:center;justify-content:center;backdrop-filter:blur(4px);padding:16px}
        .modal-content{background:var(--bg-primary);border-radius:26px;padding:22px 20px;max-width:500px;width:100%;max-height:88vh;overflow-y:auto;animation:modalIn .3s ease;border:1px solid var(--border-color);color:var(--text-primary)}
        @keyframes modalIn{from{opacity:0;transform:scale(.92)}to{opacity:1;transform:scale(1)}}
        .modal-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
        .modal-header h3{color:var(--text-primary);font-size:1.2rem}
        .close-btn{background:none;border:none;font-size:1.8rem;cursor:pointer;color:var(--text-tertiary);line-height:1;padding:0 6px;transition:color .2s}
        .close-btn:hover{color:var(--danger)}
        .modal-footer{display:flex;gap:10px;justify-content:flex-end;margin-top:20px;flex-wrap:wrap}
        .modal-btn{padding:12px 22px;border:none;border-radius:14px;font-weight:600;cursor:pointer;transition:all .2s;font-size:.95rem;touch-action:manipulation;flex:1 1 auto}
        .modal-btn.primary{background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff}
        .modal-btn.secondary{background:var(--bg-tertiary);color:var(--text-primary);border:1px solid var(--border-color)}
        .modal-btn.danger{background:var(--danger);color:#fff}
        .modal-btn:active{transform:scale(.97)}
        
        /* FORM ELEMENTS IN MODAL */
        .form-row{margin-bottom:16px}
        .form-row label{display:block;margin-bottom:6px;color:var(--text-secondary);font-size:.9rem;font-weight:500}
        .form-row input,.form-row textarea{width:100%;padding:12px 16px;border:2px solid var(--border-color);border-radius:14px;background:var(--input-bg);color:var(--text-primary);font-size:15px;font-family:inherit;transition:all .2s;-webkit-appearance:none}
        .form-row input:focus,.form-row textarea:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
        .form-hint{font-size:.75rem;color:var(--text-tertiary);margin-top:4px}
        .form-hint.warn{color:var(--warning)}
        .input-error{border-color:var(--danger)!important}
        
        /* ACCOUNT SETTINGS */
        .settings-section{background:var(--bg-tertiary);border-radius:16px;padding:16px;margin-bottom:14px;border:1px solid var(--border-color)}
        .settings-section h4{color:var(--text-primary);margin-bottom:12px;font-size:.95rem;display:flex;align-items:center;gap:6px}
        .avatar-upload-area{display:flex;align-items:center;gap:16px;margin-bottom:12px}
        .avatar-preview{width:72px;height:72px;border-radius:20px;background:linear-gradient(135deg,var(--primary),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-size:2rem;font-weight:700;overflow:hidden;flex-shrink:0;box-shadow:0 4px 12px rgba(59,130,246,.25)}
        .avatar-preview img{width:100%;height:100%;object-fit:cover;border-radius:20px}
        .avatar-buttons{display:flex;flex-direction:column;gap:8px}
        .btn-sm{padding:8px 16px;border:none;border-radius:10px;font-size:.85rem;font-weight:600;cursor:pointer;transition:all .2s;touch-action:manipulation}
        .btn-sm.primary{background:linear-gradient(135deg,var(--primary),#8b5cf6);color:#fff}
        .btn-sm.secondary{background:var(--bg-primary);border:1px solid var(--border-color);color:var(--text-primary)}
        .btn-sm.danger{background:rgba(239,68,68,.1);color:var(--danger);border:1px solid rgba(239,68,68,.2)}
        
        /* MISC */
        .friend-request-item,.group-invite-item,.member-item{display:flex;align-items:center;justify-content:space-between;padding:12px;background:var(--bg-tertiary);border-radius:14px;margin-bottom:10px;border:1px solid var(--border-color);gap:10px;flex-wrap:wrap}
        .member-role{font-size:.72rem;padding:3px 9px;background:var(--primary);color:#fff;border-radius:20px}
        .theme-toggle{margin:8px 12px;flex-shrink:0}
        .theme-toggle button{width:100%;padding:12px;border:2px solid var(--border-color);border-radius:18px;background:var(--bg-tertiary);color:var(--text-primary);cursor:pointer;font-size:.95rem;display:flex;align-items:center;justify-content:center;gap:8px;transition:all .2s;touch-action:manipulation}
        .theme-toggle button:active{border-color:var(--primary);transform:scale(.98)}
        .badge{background:var(--danger);color:#fff;border-radius:20px;padding:2px 7px;font-size:.7rem;margin-left:5px}
        .online-dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--success);margin-left:4px}
        .security-badge{font-size:.75rem;color:var(--text-tertiary);text-align:center;padding:10px;border-top:1px solid var(--border-color);flex-shrink:0}
        .toast{position:fixed;bottom:80px;left:50%;transform:translateX(-50%);background:#1e293b;color:#fff;padding:10px 20px;border-radius:20px;font-size:.85rem;z-index:9999;opacity:0;transition:opacity .3s;pointer-events:none;white-space:nowrap;max-width:90vw;text-align:center}
        .toast.show{opacity:1}
        ::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:var(--bg-tertiary)}::-webkit-scrollbar-thumb{background:var(--primary);border-radius:3px}
        .date-divider{text-align:center;margin:8px 0;color:var(--text-tertiary);font-size:.75rem}
        .sidebar-bottom{padding:8px 12px;display:flex;gap:6px;justify-content:space-around;border-top:1px solid var(--border-color);flex-shrink:0}
    </style>
</head>
<body>
<div id="toast" class="toast"></div>
<div class="app-container" id="appContainer">
    <div class="sidebar" id="sidebar">
        <div class="sidebar-header">
            <div class="user-profile" onclick="showAccountSettings()" title="Настройки аккаунта">
                <div class="avatar online" id="sidebarAvatar">
                    <?php if ($current_user['avatar']): ?>
                        <img src="<?php echo AVATAR_DIR . htmlspecialchars($current_user['avatar']); ?>" alt="avatar">
                    <?php else: ?>
                        <?php echo strtoupper(substr($current_user['username'], 0, 1)); ?>
                    <?php endif; ?>
                </div>
                <div class="user-info">
                    <h4><?php echo htmlspecialchars($current_user['username']); ?></h4>
                    <p>⚙️ Нажмите для настроек</p>
                </div>
            </div>
        </div>
        <div class="search-bar">
            <input type="text" id="searchInput" placeholder="🔍 Поиск пользователей..." onkeyup="searchUsers(event)" autocomplete="off">
            <div id="searchResults" class="search-results"></div>
        </div>
        <div class="tabs">
            <button class="tab-btn active" onclick="switchTab('chats', this)">Чаты</button>
            <button class="tab-btn" onclick="switchTab('groups', this)">Группы</button>
            <button class="tab-btn" onclick="switchTab('contacts', this)">Контакты</button>
        </div>
        <div class="chat-list" id="chatList"></div>
        <div class="theme-toggle">
            <button onclick="toggleTheme()">
                <span id="themeIcon"><?php echo $theme === 'dark' ? '☀️' : '🌙'; ?></span>
                <span id="themeText"><?php echo $theme === 'dark' ? 'Светлая тема' : 'Тёмная тема'; ?></span>
            </button>
        </div>
        <div class="sidebar-bottom">
            <button class="action-btn" onclick="showRequestsModal()" title="Запросы">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>
                <span id="requestsBadge" class="badge" style="display:none">0</span>
            </button>
            <button class="action-btn" onclick="showCreateGroupModal()" title="Создать группу">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M5.5 20v-2a5 5 0 0 1 10 0v2"/><line x1="18" y1="8" x2="22" y2="8"/><line x1="20" y1="6" x2="20" y2="10"/></svg>
            </button>
            <button class="action-btn" onclick="logout()" title="Выйти">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
            </button>
        </div>
        <div class="security-badge">🔒 AES-256-GCM</div>
    </div>
    
    <div class="main">
        <div class="chat-header" id="chatHeader">
            <button class="menu-toggle" onclick="toggleSidebar()" id="menuToggle">
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/></svg>
            </button>
            <div class="chat-header-info">
                <div class="chat-header-avatar" id="chatAvatar">👤</div>
                <div class="chat-header-text">
                    <h3 id="chatTitle">Выберите чат</h3>
                    <p id="chatStatus">Начните общение</p>
                </div>
            </div>
            <div class="chat-header-actions">
                <button class="action-btn" onclick="showGroupInfo()" id="groupInfoBtn" style="display:none" title="Участники">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                </button>
                <button class="action-btn" onclick="showChatActions()" id="chatActionsBtn" style="display:none" title="Действия">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/><circle cx="5" cy="12" r="1"/></svg>
                </button>
            </div>
        </div>
        <div class="messages-container" id="messages"></div>
        <div class="emoji-picker" id="emojiPicker"></div>
        <div class="message-form">
            <div class="message-actions">
                <button class="attach-btn" onclick="document.getElementById('fileInput').click()" title="Прикрепить">📎</button>
                <input type="file" id="fileInput" style="display:none" onchange="uploadFile()" accept="image/jpeg,image/png,image/gif,image/webp,application/pdf,.doc,.docx,text/plain">
                <button class="emoji-btn" onclick="toggleEmojiPicker()" title="Эмодзи">😊</button>
            </div>
            <div class="message-input-wrapper">
                <textarea id="messageInput" class="message-input" placeholder="Сообщение..." rows="1" onkeydown="handleKeyPress(event)" oninput="handleMessageInput(this)" maxlength="<?php echo MAX_MESSAGE_LENGTH; ?>"></textarea>
                <div class="char-counter" id="charCounter">0 / <?php echo MAX_MESSAGE_LENGTH; ?></div>
            </div>
            <button class="send-btn" onclick="sendMessage()" title="Отправить">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
            </button>
        </div>
    </div>
</div>

<!-- === ACCOUNT SETTINGS MODAL === -->
<div id="accountModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3>⚙️ Настройки аккаунта</h3>
            <button class="close-btn" onclick="hideModal('accountModal')">&times;</button>
        </div>
        <div class="settings-section">
            <h4>📷 Аватар</h4>
            <div class="avatar-upload-area">
                <div class="avatar-preview" id="avatarPreviewBig">
                    <?php if ($current_user['avatar']): ?>
                        <img src="<?php echo AVATAR_DIR . htmlspecialchars($current_user['avatar']); ?>" alt="avatar">
                    <?php else: ?>
                        <?php echo strtoupper(substr($current_user['username'], 0, 1)); ?>
                    <?php endif; ?>
                </div>
                <div class="avatar-buttons">
                    <button class="btn-sm primary" onclick="document.getElementById('avatarInput').click()">📤 Загрузить фото</button>
                    <button class="btn-sm danger" onclick="deleteAvatar()" id="deleteAvatarBtn" <?php echo $current_user['avatar'] ? '' : 'style="display:none"'; ?>>🗑️ Удалить</button>
                </div>
                <input type="file" id="avatarInput" style="display:none" onchange="uploadAvatar()" accept="image/jpeg,image/png,image/gif,image/webp">
            </div>
            <div class="form-hint">JPG, PNG, GIF, WEBP · До 3 МБ · Автоматически обрезается до квадрата 256×256</div>
        </div>
        
        <div class="settings-section">
            <h4>👤 Аккаунт: <span style="color:var(--primary)"><?php echo htmlspecialchars($current_user['username']); ?></span></h4>
            <div class="form-row">
                <label>Текущий пароль <span style="color:var(--danger)">*</span></label>
                <input type="password" id="currentPassword" placeholder="Обязателен для изменений" maxlength="<?php echo MAX_PASSWORD_LENGTH; ?>" autocomplete="current-password">
                <div class="form-hint">Требуется для сохранения любых изменений</div>
            </div>
        </div>
        
        <div class="settings-section">
            <h4>📧 Изменить Email</h4>
            <div class="form-row">
                <label>Новый Email</label>
                <input type="email" id="newEmail" placeholder="новый@email.com" maxlength="<?php echo MAX_EMAIL_LENGTH; ?>" oninput="validateEmailInput(this)" autocomplete="email">
                <div class="form-hint" id="emailHint">Текущий: <?php echo htmlspecialchars($current_user['email'] ?? '(не указан)'); ?> · Макс. <?php echo MAX_EMAIL_LENGTH; ?> символов</div>
            </div>
        </div>
        
        <div class="settings-section">
            <h4>🔑 Изменить пароль</h4>
            <div class="form-row">
                <label>Новый пароль</label>
                <input type="password" id="newPassword" placeholder="Минимум <?php echo MIN_PASSWORD_LENGTH; ?> символов" minlength="<?php echo MIN_PASSWORD_LENGTH; ?>" maxlength="<?php echo MAX_PASSWORD_LENGTH; ?>" oninput="checkNewPasswordStrength(this)" autocomplete="new-password">
                <div class="password-strength-mini"><div class="strength-bar-mini" id="settingsStrengthBar"></div></div>
                <div class="form-hint" id="newPwHint">От <?php echo MIN_PASSWORD_LENGTH; ?> до <?php echo MAX_PASSWORD_LENGTH; ?> символов: заглавные, строчные, цифры</div>
            </div>
            <div class="form-row">
                <label>Подтвердите новый пароль</label>
                <input type="password" id="confirmNewPassword" placeholder="Повторите новый пароль" maxlength="<?php echo MAX_PASSWORD_LENGTH; ?>" oninput="checkNewPasswordMatch(this)" autocomplete="new-password">
            </div>
        </div>
        
        <div id="accountError" style="color:var(--danger);font-size:.85rem;margin-bottom:10px;display:none;padding:10px;background:rgba(239,68,68,.1);border-radius:10px;border:1px solid rgba(239,68,68,.2)"></div>
        <div id="accountSuccess" style="color:var(--success);font-size:.85rem;margin-bottom:10px;display:none;padding:10px;background:rgba(16,185,129,.1);border-radius:10px;border:1px solid rgba(16,185,129,.2)"></div>
        
        <div class="modal-footer">
            <button class="modal-btn secondary" onclick="hideModal('accountModal')">Закрыть</button>
            <button class="modal-btn primary" onclick="saveAccountSettings()">💾 Сохранить</button>
        </div>
    </div>
</div>
<style>
.password-strength-mini{height:3px;background:var(--border-color);border-radius:2px;margin-top:6px;overflow:hidden}
.strength-bar-mini{height:100%;border-radius:2px;transition:all .3s;width:0}
</style>

<!-- === REQUESTS MODAL === -->
<div id="requestsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3>👥 Запросы и приглашения</h3><button class="close-btn" onclick="hideModal('requestsModal')">&times;</button></div>
        <h4 style="margin-bottom:10px;color:var(--text-secondary);font-size:.9rem">Запросы в друзья</h4>
        <div id="friendRequestsList" style="color:var(--text-tertiary);text-align:center;padding:20px">Загрузка...</div>
        <h4 style="margin:18px 0 10px;color:var(--text-secondary);font-size:.9rem">Приглашения в группы</h4>
        <div id="groupInvitesList" style="color:var(--text-tertiary);text-align:center;padding:20px">Загрузка...</div>
    </div>
</div>

<!-- === CREATE GROUP MODAL === -->
<div id="createGroupModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3>➕ Создать группу</h3><button class="close-btn" onclick="hideModal('createGroupModal')">&times;</button></div>
        <div class="form-row">
            <label>Название группы</label>
            <input type="text" id="groupName" placeholder="Моя группа" maxlength="<?php echo MAX_GROUP_NAME_LENGTH; ?>" oninput="document.getElementById('groupNameCount').textContent=this.value.length+'/<?php echo MAX_GROUP_NAME_LENGTH; ?>'">
            <div class="form-hint">От 3 до <?php echo MAX_GROUP_NAME_LENGTH; ?> символов · <span id="groupNameCount">0/<?php echo MAX_GROUP_NAME_LENGTH; ?></span></div>
        </div>
        <div class="form-row">
            <label>Описание <span style="color:var(--text-tertiary)">(необязательно)</span></label>
            <textarea id="groupDescription" placeholder="Описание группы..." rows="3" maxlength="<?php echo MAX_GROUP_DESC_LENGTH; ?>" style="resize:none"></textarea>
            <div class="form-hint">Макс. <?php echo MAX_GROUP_DESC_LENGTH; ?> символов</div>
        </div>
        <div class="modal-footer">
            <button class="modal-btn secondary" onclick="hideModal('createGroupModal')">Отмена</button>
            <button class="modal-btn primary" onclick="createGroup()">Создать</button>
        </div>
    </div>
</div>

<!-- GROUP INFO -->
<div id="groupInfoModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3 id="groupInfoName">Группа</h3><button class="close-btn" onclick="hideModal('groupInfoModal')">&times;</button></div>
        <div id="groupDescriptionDisplay" style="margin-bottom:16px;padding:10px 14px;background:var(--bg-tertiary);border-radius:12px;font-size:.9rem;color:var(--text-secondary)"></div>
        <h4 style="margin-bottom:10px;color:var(--text-secondary);font-size:.85rem">Участники</h4>
        <div id="groupMembersList"></div>
        <h4 style="margin:16px 0 10px;color:var(--text-secondary);font-size:.85rem">Пригласить друзей</h4>
        <div id="friendsToInvite"></div>
        <div style="margin-top:16px;display:flex;gap:8px;flex-wrap:wrap">
            <button class="modal-btn danger" onclick="leaveGroup()" id="leaveGroupBtn" style="flex:1">Покинуть</button>
            <button class="modal-btn danger" onclick="deleteGroup()" id="deleteGroupBtn" style="flex:1">Удалить</button>
        </div>
    </div>
</div>

<!-- CHAT ACTIONS -->
<div id="chatActionsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3>Действия с чатом</h3><button class="close-btn" onclick="hideModal('chatActionsModal')">&times;</button></div>
        <button class="modal-btn danger" style="width:100%;margin-bottom:8px" onclick="deleteChat()">🗑️ Удалить чат</button>
        <button class="modal-btn secondary" style="width:100%" onclick="hideModal('chatActionsModal')">Отмена</button>
    </div>
</div>

<!-- MESSAGE ACTIONS -->
<div id="messageActionsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3>Сообщение</h3><button class="close-btn" onclick="hideModal('messageActionsModal')">&times;</button></div>
        <button class="modal-btn primary" style="width:100%;margin-bottom:8px" onclick="editMessage()">✏️ Редактировать</button>
        <button class="modal-btn danger" style="width:100%;margin-bottom:8px" onclick="deleteMessage(true)">🗑️ Удалить для всех</button>
        <button class="modal-btn secondary" style="width:100%" onclick="hideModal('messageActionsModal')">Отмена</button>
    </div>
</div>

<!-- EDIT MESSAGE -->
<div id="editMessageModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3>✏️ Редактировать</h3><button class="close-btn" onclick="hideModal('editMessageModal')">&times;</button></div>
        <div class="form-row">
            <textarea id="editMessageText" rows="4" maxlength="<?php echo MAX_MESSAGE_LENGTH; ?>" style="resize:none"></textarea>
            <div class="form-hint"><span id="editCharCount">0</span> / <?php echo MAX_MESSAGE_LENGTH; ?></div>
        </div>
        <div class="modal-footer">
            <button class="modal-btn secondary" onclick="hideModal('editMessageModal')">Отмена</button>
            <button class="modal-btn primary" onclick="saveEditedMessage()">Сохранить</button>
        </div>
    </div>
</div>

<!-- IMAGE PREVIEW -->
<div id="imagePreviewModal" class="modal" onclick="hideModal('imagePreviewModal')">
    <div class="modal-content" style="max-width:95%;background:transparent;box-shadow:none;border:none" onclick="event.stopPropagation()">
        <img id="previewImage" src="" alt="Preview" style="max-width:100%;max-height:85vh;border-radius:14px;display:block;margin:auto">
    </div>
</div>

<!-- REACTIONS -->
<div id="reactionsModal" class="modal">
    <div class="modal-content">
        <div class="modal-header"><h3>Реакции</h3><button class="close-btn" onclick="hideModal('reactionsModal')">&times;</button></div>
        <div id="reactionsList"></div>
    </div>
</div>

<script>
const currentUser = <?php echo json_encode(['id' => $current_user['id'], 'username' => $current_user['username'], 'avatar' => $current_user['avatar'] ?? null]); ?>;
const csrfToken = '<?php echo Security::generateCSRFToken(); ?>';
const UPLOAD_DIR = '<?php echo UPLOAD_DIR; ?>';
const AVATAR_DIR = '<?php echo AVATAR_DIR; ?>';
const LIMITS = {
    maxMessage: <?php echo MAX_MESSAGE_LENGTH; ?>,
    minPw: <?php echo MIN_PASSWORD_LENGTH; ?>,
    maxPw: <?php echo MAX_PASSWORD_LENGTH; ?>,
    minUn: <?php echo MIN_USERNAME_LENGTH; ?>,
    maxUn: <?php echo MAX_USERNAME_LENGTH; ?>,
    maxEmail: <?php echo MAX_EMAIL_LENGTH; ?>
};

let activeChat = null, activeGroup = null, friends = [], groups = [], messages = [];
let selectedMessageId = null;
let currentTab = 'chats';
const emojis = ['😊','😂','❤️','👍','😢','😡','🎉','🔥','✨','🥳','🤔','😎','💯','⭐','👏','🙏','😍','🤣','😭','✅','❌','👋','🤝','😴','🙃','💪','🤯','😅','🤦','🫡'];

// === TOAST ===
function showToast(msg, dur = 2500) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.classList.add('show');
    setTimeout(() => t.classList.remove('show'), dur);
}

// === INIT ===
document.addEventListener('DOMContentLoaded', () => {
    loadFriends();
    loadGroups();
    loadEmojiPicker();
    loadRequestsCount();
    setInterval(loadMessages, 3000);
    setInterval(loadRequestsCount, 15000);
    setInterval(updateOnlineStatuses, 30000);
    
    document.addEventListener('click', e => {
        const sidebar = document.getElementById('sidebar');
        const menuToggle = document.getElementById('menuToggle');
        if (window.innerWidth <= 768 && sidebar.classList.contains('active') && !sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
            toggleSidebar();
        }
        if (!e.target.closest('.emoji-picker') && !e.target.closest('.emoji-btn')) {
            document.getElementById('emojiPicker').style.display = 'none';
        }
        if (!e.target.closest('.search-bar')) {
            document.getElementById('searchResults').style.display = 'none';
        }
    });
    
    document.getElementById('messages').addEventListener('scroll', function() {
        if (this.scrollTop === 0 && messages.length > 0) loadMoreMessages();
    });
});

// === EMOJI PICKER ===
function loadEmojiPicker() {
    document.getElementById('emojiPicker').innerHTML = emojis.map(e => `<div class="emoji-item" onclick="addEmoji('${e}')">${e}</div>`).join('');
}
function toggleEmojiPicker() {
    const p = document.getElementById('emojiPicker');
    p.style.display = p.style.display === 'grid' ? 'none' : 'grid';
}
function addEmoji(emoji) {
    const input = document.getElementById('messageInput');
    const pos = input.selectionStart;
    input.value = input.value.slice(0, pos) + emoji + input.value.slice(pos);
    input.focus();
    handleMessageInput(input);
    document.getElementById('emojiPicker').style.display = 'none';
}

// === MESSAGE INPUT ===
function handleMessageInput(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 100) + 'px';
    const len = el.value.length;
    const counter = document.getElementById('charCounter');
    counter.textContent = `${len} / ${LIMITS.maxMessage}`;
    if (len > LIMITS.maxMessage * 0.9) counter.className = 'char-counter danger';
    else if (len > LIMITS.maxMessage * 0.75) counter.className = 'char-counter warn';
    else counter.className = 'char-counter';
}

// === THEME ===
function toggleTheme() {
    const html = document.documentElement;
    const newTheme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-theme', newTheme);
    document.getElementById('themeIcon').textContent = newTheme === 'dark' ? '☀️' : '🌙';
    document.getElementById('themeText').textContent = newTheme === 'dark' ? 'Светлая тема' : 'Тёмная тема';
    const fd = new FormData();
    fd.append('action', 'change_theme');
    fd.append('theme', newTheme);
    fd.append('csrf_token', csrfToken);
    fetch('', {method:'POST', body:fd}).catch(console.error);
}

// === SIDEBAR ===
function toggleSidebar() { document.getElementById('sidebar').classList.toggle('active'); }

// === REQUESTS COUNT ===
function loadRequestsCount() {
    Promise.all([
        api('get_friend_requests').catch(() => ({requests:[]})),
        api('get_group_invites').catch(() => ({invites:[]}))
    ]).then(([fd, gd]) => {
        const count = (fd.requests?.length || 0) + (gd.invites?.length || 0);
        const badge = document.getElementById('requestsBadge');
        badge.style.display = count > 0 ? 'inline' : 'none';
        if (count > 0) badge.textContent = count;
    });
}

// === API HELPER ===
function api(action, extraData = {}) {
    const fd = new FormData();
    fd.append('action', action);
    fd.append('csrf_token', csrfToken);
    for (const [k, v] of Object.entries(extraData)) fd.append(k, v);
    return fetch('', {method:'POST', body:fd}).then(r => r.json());
}

// === ACCOUNT SETTINGS ===
function showAccountSettings() {
    document.getElementById('currentPassword').value = '';
    document.getElementById('newEmail').value = '';
    document.getElementById('newPassword').value = '';
    document.getElementById('confirmNewPassword').value = '';
    document.getElementById('accountError').style.display = 'none';
    document.getElementById('accountSuccess').style.display = 'none';
    document.getElementById('settingsStrengthBar').style.width = '0';
    document.getElementById('accountModal').style.display = 'flex';
}

function validateEmailInput(input) {
    const val = input.value;
    const hint = document.getElementById('emailHint');
    if (val.length > LIMITS.maxEmail) {
        hint.className = 'form-hint warn';
        hint.textContent = `Слишком длинный (${val.length}/${LIMITS.maxEmail})`;
    } else if (val.length > 0 && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val)) {
        hint.className = 'form-hint warn';
        hint.textContent = 'Неверный формат email';
    } else {
        hint.className = 'form-hint';
        hint.textContent = val.length > 0 ? `${val.length}/${LIMITS.maxEmail} символов` : `Текущий: ${currentUser.email || '(не указан)'} · Макс. ${LIMITS.maxEmail} символов`;
    }
}

function checkNewPasswordStrength(input) {
    const pw = input.value;
    const bar = document.getElementById('settingsStrengthBar');
    const hint = document.getElementById('newPwHint');
    let score = 0;
    if (pw.length >= LIMITS.minPw) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[a-z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^A-Za-z0-9]/.test(pw)) score++;
    const colors = ['#ef4444','#f59e0b','#f59e0b','#10b981','#10b981'];
    const labels = ['Очень слабый','Слабый','Средний','Сильный','Очень сильный'];
    bar.style.width = (score * 20) + '%';
    bar.style.background = pw.length > 0 ? (colors[score-1] || '#334155') : '';
    hint.textContent = pw.length > 0 ? labels[score-1] : `От ${LIMITS.minPw} до ${LIMITS.maxPw} символов`;
    hint.className = 'form-hint' + (score < 3 && pw.length > 0 ? ' warn' : '');
}

function checkNewPasswordMatch(input) {
    const newPw = document.getElementById('newPassword').value;
    input.style.borderColor = input.value && input.value !== newPw ? 'var(--danger)' : '';
}

async function saveAccountSettings() {
    const errEl = document.getElementById('accountError');
    const sucEl = document.getElementById('accountSuccess');
    errEl.style.display = 'none';
    sucEl.style.display = 'none';
    
    const currentPw = document.getElementById('currentPassword').value;
    const newEmail = document.getElementById('newEmail').value.trim();
    const newPw = document.getElementById('newPassword').value;
    const confirmPw = document.getElementById('confirmNewPassword').value;
    
    const showErr = msg => { errEl.textContent = msg; errEl.style.display = 'block'; };
    
    if (!currentPw) { showErr('Введите текущий пароль для подтверждения изменений'); return; }
    if (!newEmail && !newPw) { showErr('Укажите что-то для изменения: email или пароль'); return; }
    
    if (newEmail && newEmail.length > LIMITS.maxEmail) { showErr(`Email слишком длинный (макс. ${LIMITS.maxEmail} символов)`); return; }
    
    if (newPw) {
        if (newPw.length < LIMITS.minPw) { showErr(`Новый пароль должен быть не менее ${LIMITS.minPw} символов`); return; }
        if (newPw.length > LIMITS.maxPw) { showErr(`Новый пароль не должен превышать ${LIMITS.maxPw} символов`); return; }
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(newPw)) { showErr('Пароль должен содержать заглавные, строчные буквы и цифры'); return; }
        if (newPw !== confirmPw) { showErr('Новые пароли не совпадают'); return; }
    }
    
    try {
        const data = await api('update_account', {email: newEmail, new_password: newPw, current_password: currentPw});
        if (data.success) {
            sucEl.textContent = '✅ ' + (data.message || 'Настройки успешно обновлены');
            sucEl.style.display = 'block';
            document.getElementById('currentPassword').value = '';
            document.getElementById('newPassword').value = '';
            document.getElementById('confirmNewPassword').value = '';
            document.getElementById('settingsStrengthBar').style.width = '0';
            showToast('✅ Настройки сохранены');
        } else {
            showErr(data.error || 'Ошибка сохранения');
        }
    } catch { showErr('Ошибка соединения'); }
}

// === AVATAR ===
async function uploadAvatar() {
    const input = document.getElementById('avatarInput');
    const file = input.files[0];
    if (!file) return;
    
    const maxSize = 3 * 1024 * 1024;
    if (file.size > maxSize) { showToast('⚠️ Файл слишком большой (максимум 3 МБ)'); input.value = ''; return; }
    
    const fd = new FormData();
    fd.append('action', 'upload_avatar');
    fd.append('avatar', file);
    fd.append('csrf_token', csrfToken);
    
    showToast('⏳ Загружаем аватар...');
    
    try {
        const r = await fetch('', {method:'POST', body:fd});
        const data = await r.json();
        if (data.success) {
            const avatarUrl = data.avatar + '?t=' + Date.now();
            currentUser.avatar = data.avatar.replace(AVATAR_DIR, '');
            
            // Обновляем все аватарки
            updateAvatarElements(avatarUrl);
            document.getElementById('deleteAvatarBtn').style.display = '';
            showToast('✅ Аватар обновлён');
        } else {
            showToast('❌ ' + (data.error || 'Ошибка загрузки'));
        }
    } catch { showToast('❌ Ошибка соединения'); }
    input.value = '';
}

function updateAvatarElements(url) {
    // Sidebar avatar
    const sidebarAv = document.getElementById('sidebarAvatar');
    sidebarAv.innerHTML = `<img src="${url}" alt="avatar">`;
    
    // Settings preview
    const previewBig = document.getElementById('avatarPreviewBig');
    previewBig.innerHTML = `<img src="${url}" alt="avatar">`;
}

async function deleteAvatar() {
    if (!confirm('Удалить аватар?')) return;
    try {
        const data = await api('delete_avatar');
        if (data.success) {
            const letter = escapeHtml(currentUser.username[0].toUpperCase());
            document.getElementById('sidebarAvatar').innerHTML = letter;
            document.getElementById('avatarPreviewBig').innerHTML = letter;
            document.getElementById('deleteAvatarBtn').style.display = 'none';
            currentUser.avatar = null;
            showToast('✅ Аватар удалён');
        } else { showToast('❌ ' + data.error); }
    } catch { showToast('❌ Ошибка'); }
}

// === SEARCH ===
let searchTimeout;
function searchUsers(event) {
    if (event.key === 'Escape') { document.getElementById('searchResults').style.display = 'none'; return; }
    clearTimeout(searchTimeout);
    searchTimeout = setTimeout(async () => {
        const query = document.getElementById('searchInput').value.trim();
        if (query.length < 2) { document.getElementById('searchResults').style.display = 'none'; return; }
        try {
            const data = await api('search_users', {query});
            if (data.success) displaySearchResults(data.users);
        } catch(e) {}
    }, 300);
}

function displaySearchResults(users) {
    const div = document.getElementById('searchResults');
    if (!users.length) { div.style.display = 'none'; return; }
    const isFriend = id => friends.some(f => f.id == id);
    div.innerHTML = users.map(u => `
        <div class="search-result-item">
            <div style="width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,var(--primary),#8b5cf6);display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;flex-shrink:0;overflow:hidden">
                ${u.avatar ? `<img src="${AVATAR_DIR}${escapeHtml(u.avatar)}" style="width:100%;height:100%;object-fit:cover;border-radius:10px">` : escapeHtml(u.username[0].toUpperCase())}
            </div>
            <div style="flex:1;min-width:0">
                <div style="font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(u.username)}<span class="online-dot" style="background:${u.status==='online'?'var(--success)':'#94a3b8'}"></span></div>
                <div style="font-size:.75rem;color:var(--text-tertiary)">${u.status==='online'?'В сети':'Офлайн'}</div>
            </div>
            ${!isFriend(u.id) ? `<button class="btn-sm primary" onclick="sendFriendRequest(${u.id})">+ Добавить</button>` : '<span style="color:var(--success);font-size:.8rem">✓ Друг</span>'}
        </div>
    `).join('');
    div.style.display = 'block';
}

async function sendFriendRequest(userId) {
    try {
        const data = await api('send_friend_request', {user_id: userId});
        if (data.success) { showToast('✅ Запрос отправлен!'); document.getElementById('searchResults').style.display = 'none'; document.getElementById('searchInput').value = ''; }
        else showToast('❌ ' + (data.error || 'Ошибка'));
    } catch { showToast('❌ Ошибка'); }
}

// === REQUESTS MODAL ===
function showRequestsModal() {
    document.getElementById('requestsModal').style.display = 'flex';
    loadFriendRequests();
    loadGroupInvites();
}

async function loadFriendRequests() {
    try {
        const data = await api('get_friend_requests');
        if (data.success) displayFriendRequests(data.requests);
    } catch {}
}
function displayFriendRequests(reqs) {
    const div = document.getElementById('friendRequestsList');
    if (!reqs.length) { div.innerHTML = '<p style="color:var(--text-tertiary);text-align:center">Нет запросов</p>'; return; }
    div.innerHTML = reqs.map(r => `
        <div class="friend-request-item">
            <div style="display:flex;align-items:center;gap:10px;min-width:0">
                <div class="avatar" style="width:40px;height:40px;font-size:.9rem;overflow:hidden">
                    ${r.avatar ? `<img src="${AVATAR_DIR}${escapeHtml(r.avatar)}" style="width:100%;height:100%;object-fit:cover">` : escapeHtml(r.username[0].toUpperCase())}
                </div>
                <div style="min-width:0">
                    <div style="font-weight:600;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(r.username)}</div>
                    <div style="font-size:.75rem;color:var(--text-tertiary)">Хочет добавить вас</div>
                </div>
            </div>
            <div style="display:flex;gap:6px">
                <button class="btn-sm primary" onclick="respondToFriendRequest(${r.id},true)">✓</button>
                <button class="btn-sm secondary" onclick="respondToFriendRequest(${r.id},false)">✗</button>
            </div>
        </div>
    `).join('');
}
async function loadGroupInvites() {
    try {
        const data = await api('get_group_invites');
        if (data.success) displayGroupInvites(data.invites);
    } catch {}
}
function displayGroupInvites(invites) {
    const div = document.getElementById('groupInvitesList');
    if (!invites.length) { div.innerHTML = '<p style="color:var(--text-tertiary);text-align:center">Нет приглашений</p>'; return; }
    div.innerHTML = invites.map(i => `
        <div class="group-invite-item">
            <div style="min-width:0">
                <div style="font-weight:600;color:var(--text-primary)">${escapeHtml(i.group_name)}</div>
                <div style="font-size:.75rem;color:var(--text-tertiary)">от ${escapeHtml(i.inviter_name)}</div>
            </div>
            <div style="display:flex;gap:6px">
                <button class="btn-sm primary" onclick="respondToGroupInvite(${i.id},true)">✓</button>
                <button class="btn-sm secondary" onclick="respondToGroupInvite(${i.id},false)">✗</button>
            </div>
        </div>
    `).join('');
}
async function respondToFriendRequest(id, accept) {
    try {
        const data = await api('respond_friend_request', {request_id: id, accept: accept});
        if (data.success) { loadFriends(); loadFriendRequests(); loadRequestsCount(); showToast(accept ? '✅ Запрос принят!' : '❌ Запрос отклонён'); }
        else showToast('❌ ' + data.error);
    } catch {}
}
async function respondToGroupInvite(id, accept) {
    try {
        const data = await api('respond_group_invite', {invite_id: id, accept: accept});
        if (data.success) { loadGroups(); loadGroupInvites(); loadRequestsCount(); showToast(accept ? '✅ Вы вступили в группу!' : 'Приглашение отклонено'); }
    } catch {}
}

// === FRIENDS & GROUPS ===
async function loadFriends() {
    try {
        const data = await api('get_friends');
        if (data.success) { friends = data.friends; renderChatList(); }
    } catch {}
}
async function loadGroups() {
    try {
        const data = await api('get_groups');
        if (data.success) { groups = data.groups; renderChatList(); }
    } catch {}
}
async function updateOnlineStatuses() {
    if (!friends.length) return;
    try {
        const data = await api('get_online_status', {user_ids: JSON.stringify(friends.map(f => f.id))});
        if (data.success) {
            friends.forEach(f => { if (data.statuses[f.id]) { f.status = data.statuses[f.id].status; f.last_seen = data.statuses[f.id].last_seen; } });
            renderChatList();
            if (activeChat) updateChatHeader();
        }
    } catch {}
}

// === RENDER CHAT LIST ===
function renderChatList() {
    const list = document.getElementById('chatList');
    let html = '';
    const showFriends = currentTab !== 'groups';
    const showGroups = currentTab !== 'contacts';
    
    if (showFriends) {
        friends.forEach(f => {
            const online = f.status === 'online';
            const avatarHtml = f.avatar
                ? `<img src="${AVATAR_DIR}${escapeHtml(f.avatar)}?t=1" style="width:100%;height:100%;object-fit:cover;border-radius:14px">`
                : escapeHtml(f.username[0].toUpperCase());
            html += `
                <div class="chat-item ${activeChat == f.id ? 'active' : ''}" onclick="openChat(${f.id})">
                    <div class="chat-avatar" style="position:relative">${avatarHtml}${online ? '<span class="online-dot" style="position:absolute;bottom:2px;right:2px;border:2px solid var(--bg-secondary)"></span>' : ''}</div>
                    <div class="chat-info">
                        <div class="chat-name">${escapeHtml(f.username)}</div>
                        <div class="chat-last-message">${online ? '🟢 В сети' : timeSince(f.last_seen)}</div>
                    </div>
                    <div class="chat-actions">
                        <button class="chat-action-btn" onclick="event.stopPropagation();deleteChatById(${f.id},'user')" title="Удалить">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        </button>
                    </div>
                </div>`;
        });
    }
    
    if (showGroups) {
        groups.forEach(g => {
            html += `
                <div class="chat-item ${activeGroup == g.id ? 'active' : ''}" onclick="openGroup(${g.id})">
                    <div class="chat-avatar">#</div>
                    <div class="chat-info">
                        <div class="chat-name">${escapeHtml(g.name)}</div>
                        <div class="chat-last-message">👥 ${g.member_count || 0} участников</div>
                    </div>
                    <div class="chat-actions">
                        ${g.creator_id == currentUser.id ? `<button class="chat-action-btn" onclick="event.stopPropagation();deleteChatById(${g.id},'group')" title="Удалить">
                            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                        </button>` : ''}
                    </div>
                </div>`;
        });
    }
    
    if (!html) html = '<p style="text-align:center;color:var(--text-tertiary);padding:40px 16px;font-size:.9rem">Нет чатов<br><small>Найдите друзей через поиск 🔍</small></p>';
    list.innerHTML = html;
}

function timeSince(dateStr) {
    if (!dateStr) return 'Офлайн';
    const s = Math.floor((Date.now() - new Date(dateStr)) / 1000);
    if (s < 60) return 'был(а) только что';
    if (s < 3600) return `был(а) ${Math.floor(s/60)} мин. назад`;
    if (s < 86400) return `был(а) ${Math.floor(s/3600)} ч. назад`;
    return `был(а) ${Math.floor(s/86400)} д. назад`;
}

function switchTab(tab, btn) {
    currentTab = tab;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    if (btn) btn.classList.add('active');
    renderChatList();
}

// === OPEN CHAT / GROUP ===
function openChat(userId) {
    activeChat = userId;
    activeGroup = null;
    messages = [];
    document.getElementById('messages').innerHTML = '';
    updateChatHeader();
    loadMessages();
    renderChatList();
    document.getElementById('groupInfoBtn').style.display = 'none';
    document.getElementById('chatActionsBtn').style.display = 'flex';
    if (window.innerWidth <= 768) toggleSidebar();
}
function openGroup(groupId) {
    activeGroup = groupId;
    activeChat = null;
    messages = [];
    document.getElementById('messages').innerHTML = '';
    updateChatHeader();
    loadMessages();
    renderChatList();
    document.getElementById('groupInfoBtn').style.display = 'flex';
    document.getElementById('chatActionsBtn').style.display = 'none';
    if (window.innerWidth <= 768) toggleSidebar();
}

function updateChatHeader() {
    const titleEl = document.getElementById('chatTitle');
    const statusEl = document.getElementById('chatStatus');
    const avatarEl = document.getElementById('chatAvatar');
    
    if (activeGroup) {
        const g = groups.find(g => g.id == activeGroup);
        titleEl.textContent = g ? g.name : 'Группа';
        statusEl.textContent = g ? `${g.member_count || 0} участников` : 'Группа';
        avatarEl.innerHTML = '#';
    } else if (activeChat) {
        const f = friends.find(f => f.id == activeChat);
        titleEl.textContent = f ? f.username : 'Пользователь';
        statusEl.textContent = f?.status === 'online' ? '🟢 В сети' : '⚫ Офлайн';
        avatarEl.innerHTML = f?.avatar
            ? `<img src="${AVATAR_DIR}${escapeHtml(f.avatar)}" style="width:100%;height:100%;object-fit:cover;border-radius:14px">`
            : (f ? escapeHtml(f.username[0].toUpperCase()) : '👤');
    } else {
        titleEl.textContent = 'Выберите чат';
        statusEl.textContent = 'Начните общение';
        avatarEl.innerHTML = '👤';
        document.getElementById('groupInfoBtn').style.display = 'none';
        document.getElementById('chatActionsBtn').style.display = 'none';
    }
}

// === DELETE CHAT ===
async function deleteChatById(id, type) {
    const msg = type === 'user' ? 'Удалить чат? Пользователь будет удалён из друзей.' : 'Удалить группу?';
    if (!confirm(msg)) return;
    const params = type === 'user' ? {chat_with: id} : {group_id: id};
    try {
        const data = await api('delete_chat', params);
        if (data.success) {
            if (type === 'user') { friends = friends.filter(f => f.id != id); if (activeChat == id) { activeChat = null; updateChatHeader(); document.getElementById('messages').innerHTML = ''; } }
            else { groups = groups.filter(g => g.id != id); if (activeGroup == id) { activeGroup = null; updateChatHeader(); document.getElementById('messages').innerHTML = ''; } }
            renderChatList();
            showToast('✅ Удалено');
            if (type === 'user') loadFriends();
        } else showToast('❌ ' + (data.error || 'Ошибка'));
    } catch { showToast('❌ Ошибка'); }
}

// === CHAT ACTIONS ===
function showChatActions() { document.getElementById('chatActionsModal').style.display = 'flex'; }
async function deleteChat() {
    const params = activeGroup ? {group_id: activeGroup} : {chat_with: activeChat};
    if (!confirm('Удалить чат?')) return;
    try {
        const data = await api('delete_chat', params);
        if (data.success) {
            hideModal('chatActionsModal');
            if (activeGroup) groups = groups.filter(g => g.id != activeGroup);
            else { friends = friends.filter(f => f.id != activeChat); loadFriends(); }
            activeChat = null; activeGroup = null;
            renderChatList(); updateChatHeader();
            document.getElementById('messages').innerHTML = '';
            showToast('✅ Удалено');
        } else showToast('❌ ' + data.error);
    } catch {}
}

// === MESSAGES ===
async function loadMessages() {
    if (!activeChat && !activeGroup) return;
    const params = activeGroup ? {group_id: activeGroup} : {chat_with: activeChat};
    try {
        const data = await api('get_messages', params);
        if (data.success && JSON.stringify(messages) !== JSON.stringify(data.messages)) {
            messages = data.messages;
            displayMessages();
        }
    } catch {}
}

async function loadMoreMessages() {
    if (!messages.length) return;
    const params = activeGroup ? {group_id: activeGroup, before_id: messages[0].id} : {chat_with: activeChat, before_id: messages[0].id};
    try {
        const data = await api('get_messages', params);
        if (data.success && data.messages.length > 0) {
            const container = document.getElementById('messages');
            const oldHeight = container.scrollHeight;
            messages = [...data.messages, ...messages];
            displayMessages(true);
            container.scrollTop = container.scrollHeight - oldHeight;
        }
    } catch {}
}

function displayMessages(keepScroll = false) {
    const container = document.getElementById('messages');
    if (!messages.length) { container.innerHTML = '<p style="text-align:center;color:var(--text-tertiary);padding:40px;font-size:.9rem">Нет сообщений. Начните общение! 👋</p>'; return; }
    
    let html = '';
    let lastDate = null;
    
    messages.forEach(msg => {
        const date = new Date(msg.sent_at).toDateString();
        if (date !== lastDate) {
            html += `<div class="date-divider">${formatDate(msg.sent_at)}</div>`;
            lastDate = date;
        }
        const own = msg.sender_id == currentUser.id;
        const time = new Date(msg.sent_at).toLocaleTimeString('ru-RU', {hour:'2-digit',minute:'2-digit'});
        const avatarHtml = msg.avatar
            ? `<img src="${AVATAR_DIR}${escapeHtml(msg.avatar)}" style="width:100%;height:100%;object-fit:cover;border-radius:10px">`
            : (msg.username ? escapeHtml(msg.username[0].toUpperCase()) : '👤');
        
        html += `<div class="message-wrapper ${own ? 'own' : ''}" data-id="${msg.id}" ondblclick="selectMessage(${msg.id})" oncontextmenu="event.preventDefault();selectMessage(${msg.id})">
            <div class="message-avatar">${avatarHtml}</div>
            <div class="message-content">
                <div class="message-sender">${own ? 'Вы' : escapeHtml(msg.username || '')}</div>
                ${msg.type === 'image'
                    ? `<img src="${UPLOAD_DIR}${escapeHtml(msg.file_path)}" class="message-image" onclick="event.stopPropagation();showImagePreview('${UPLOAD_DIR}${escapeHtml(msg.file_path)}')" loading="lazy">`
                    : msg.type === 'file'
                    ? `<div class="message-file" onclick="event.stopPropagation();downloadFile('${escapeHtml(msg.file_path)}')">📎 <span style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escapeHtml(msg.file_name)}</span><span style="font-size:.7rem;flex-shrink:0">${fmtSize(msg.file_size)}</span></div>`
                    : `<div class="message-text">${escapeHtml(msg.message || '')}</div>`
                }
                <div class="message-reactions" id="rxn-${msg.id}"></div>
                <div class="message-time">${time}${msg.is_edited ? ' <i style="opacity:.7">(ред.)</i>' : ''}${activeGroup && msg.read_count > 1 ? ` ✓${msg.read_count}` : (!activeGroup && msg.read_count > 0 && own ? ' ✓' : '')}</div>
            </div>
        </div>`;
    });
    
    container.innerHTML = html;
    messages.forEach(m => loadReactions(m.id));
    if (!keepScroll) container.scrollTop = container.scrollHeight;
}

async function loadReactions(msgId) {
    try {
        const data = await api('get_reactions', {message_id: msgId});
        if (data.success) renderReactions(msgId, data.reactions);
    } catch {}
}
function renderReactions(msgId, reactions) {
    const el = document.getElementById(`rxn-${msgId}`);
    if (!el) return;
    if (!reactions.length) { el.innerHTML = ''; return; }
    const groups = {};
    reactions.forEach(r => { if (!groups[r.reaction]) groups[r.reaction] = 0; groups[r.reaction]++; });
    el.innerHTML = Object.entries(groups).map(([r, c]) => `<div class="reaction-badge" onclick="showReactions('${msgId}','${escapeHtml(r)}')">${escapeHtml(r)} ${c}</div>`).join('');
}

async function showReactions(msgId, reaction) {
    try {
        const data = await api('get_reactions', {message_id: msgId});
        if (data.success) {
            const filtered = data.reactions.filter(r => r.reaction === reaction);
            document.getElementById('reactionsList').innerHTML = `<h4 style="margin-bottom:10px;font-size:1.1rem">${escapeHtml(reaction)}</h4>` +
                filtered.map(r => `<div style="padding:8px;border-bottom:1px solid var(--border-color);color:var(--text-primary)">${escapeHtml(r.username)}</div>`).join('');
            document.getElementById('reactionsModal').style.display = 'flex';
        }
    } catch {}
}

function selectMessage(msgId) {
    selectedMessageId = msgId;
    const msg = messages.find(m => m.id == msgId);
    if (msg && msg.sender_id == currentUser.id) document.getElementById('messageActionsModal').style.display = 'flex';
    else promptReaction(msgId);
}

function promptReaction(msgId) {
    const reaction = prompt('Реакция (эмодзи):');
    if (!reaction || !reaction.trim()) return;
    api('add_reaction', {message_id: msgId, reaction: reaction.trim()}).then(d => {
        if (d.success) loadReactions(msgId);
        else showToast('❌ ' + d.error);
    });
}

// === SEND MESSAGE ===
async function sendMessage() {
    const input = document.getElementById('messageInput');
    const msg = input.value.trim();
    if (!msg || (!activeChat && !activeGroup)) return;
    
    if (msg.length > LIMITS.maxMessage) {
        showToast(`❌ Сообщение слишком длинное (макс. ${LIMITS.maxMessage} символов)`);
        return;
    }
    
    const params = {message: msg};
    if (activeGroup) params.group_id = activeGroup;
    else params.receiver_id = activeChat;
    
    input.value = '';
    input.style.height = 'auto';
    document.getElementById('charCounter').textContent = `0 / ${LIMITS.maxMessage}`;
    document.getElementById('charCounter').className = 'char-counter';
    
    try {
        const data = await api('send_message', params);
        if (data.success) { messages.push(data.message); displayMessages(); }
        else showToast('❌ ' + (data.error || 'Ошибка отправки'));
    } catch { showToast('❌ Ошибка соединения'); }
}

// === EDIT / DELETE ===
function editMessage() {
    const msg = messages.find(m => m.id == selectedMessageId);
    if (!msg) return;
    document.getElementById('editMessageText').value = msg.message || '';
    document.getElementById('editCharCount').textContent = (msg.message || '').length;
    document.getElementById('editMessageModal').style.display = 'flex';
    hideModal('messageActionsModal');
}
document.addEventListener('input', e => {
    if (e.target.id === 'editMessageText') {
        document.getElementById('editCharCount').textContent = e.target.value.length;
    }
});
async function saveEditedMessage() {
    const text = document.getElementById('editMessageText').value.trim();
    if (!text) return;
    if (text.length > LIMITS.maxMessage) { showToast(`❌ Слишком длинное (макс. ${LIMITS.maxMessage})`); return; }
    try {
        const data = await api('edit_message', {message_id: selectedMessageId, message: text});
        if (data.success) { hideModal('editMessageModal'); loadMessages(); showToast('✅ Изменено'); }
        else showToast('❌ ' + data.error);
    } catch {}
}
async function deleteMessage(forEveryone) {
    try {
        const data = await api('delete_message', {message_id: selectedMessageId, for_everyone: forEveryone});
        if (data.success) { hideModal('messageActionsModal'); loadMessages(); showToast('✅ Удалено'); }
        else showToast('❌ ' + data.error);
    } catch {}
}

// === UPLOAD FILE ===
async function uploadFile() {
    const input = document.getElementById('fileInput');
    const file = input.files[0];
    if (!file || (!activeChat && !activeGroup)) return;
    
    const fd = new FormData();
    fd.append('action', 'upload_file');
    fd.append('file', file);
    fd.append('csrf_token', csrfToken);
    if (activeGroup) fd.append('group_id', activeGroup);
    else fd.append('receiver_id', activeChat);
    
    showToast('⏳ Загрузка...');
    try {
        const r = await fetch('', {method:'POST', body:fd});
        const data = await r.json();
        if (data.success) { messages.push(data.message); displayMessages(); showToast('✅ Файл отправлен'); }
        else showToast('❌ ' + (data.error || 'Ошибка'));
    } catch { showToast('❌ Ошибка'); }
    input.value = '';
}

// === GROUP ===
function showCreateGroupModal() { document.getElementById('createGroupModal').style.display = 'flex'; }
async function createGroup() {
    const name = document.getElementById('groupName').value.trim();
    const desc = document.getElementById('groupDescription').value.trim();
    if (!name || name.length < 3) { showToast('❌ Название: минимум 3 символа'); return; }
    try {
        const data = await api('create_group', {name, description: desc});
        if (data.success) { hideModal('createGroupModal'); document.getElementById('groupName').value = ''; document.getElementById('groupDescription').value = ''; loadGroups(); showToast('✅ Группа создана'); }
        else showToast('❌ ' + data.error);
    } catch {}
}

async function showGroupInfo() {
    if (!activeGroup) return;
    try {
        const data = await api('get_group_members', {group_id: activeGroup});
        if (data.success) {
            const g = groups.find(g => g.id == activeGroup);
            document.getElementById('groupInfoName').textContent = g?.name || 'Группа';
            document.getElementById('groupDescriptionDisplay').textContent = g?.description || 'Нет описания';
            
            document.getElementById('groupMembersList').innerHTML = data.members.map(m => `
                <div class="member-item">
                    <div style="display:flex;align-items:center;gap:8px;min-width:0">
                        <div class="avatar" style="width:34px;height:34px;font-size:.85rem;overflow:hidden">
                            ${m.avatar ? `<img src="${AVATAR_DIR}${escapeHtml(m.avatar)}" style="width:100%;height:100%;object-fit:cover">` : escapeHtml(m.username[0].toUpperCase())}
                        </div>
                        <span style="font-weight:500;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${escapeHtml(m.username)}</span>
                        <span class="member-role">${m.role === 'admin' ? 'Админ' : 'Участник'}</span>
                    </div>
                    <span class="online-dot" style="background:${m.status==='online'?'var(--success)':'#475569'}"></span>
                </div>
            `).join('');
            
            const memberIds = data.members.map(m => m.id);
            const toInvite = friends.filter(f => !memberIds.includes(f.id));
            document.getElementById('friendsToInvite').innerHTML = toInvite.length
                ? toInvite.map(f => `<div class="member-item"><span style="color:var(--text-primary)">${escapeHtml(f.username)}</span><button class="btn-sm primary" onclick="inviteToGroup(${f.id})">➕ Пригласить</button></div>`).join('')
                : '<p style="color:var(--text-tertiary);font-size:.85rem">Все друзья уже в группе</p>';
            
            document.getElementById('leaveGroupBtn').style.display = g?.creator_id == currentUser.id ? 'none' : '';
            document.getElementById('deleteGroupBtn').style.display = g?.creator_id == currentUser.id ? '' : 'none';
            document.getElementById('groupInfoModal').style.display = 'flex';
        }
    } catch {}
}
async function inviteToGroup(userId) {
    try {
        const data = await api('invite_to_group', {group_id: activeGroup, user_id: userId});
        if (data.success) { showToast('✅ Приглашение отправлено'); showGroupInfo(); }
        else showToast('❌ ' + data.error);
    } catch {}
}
async function leaveGroup() {
    if (!confirm('Покинуть группу?')) return;
    try {
        const data = await api('leave_group', {group_id: activeGroup});
        if (data.success) { hideModal('groupInfoModal'); groups = groups.filter(g => g.id != activeGroup); activeGroup = null; renderChatList(); updateChatHeader(); document.getElementById('messages').innerHTML = ''; showToast('✅ Вы покинули группу'); }
    } catch {}
}
async function deleteGroup() {
    if (!confirm('Удалить группу? Это необратимо.')) return;
    try {
        const data = await api('delete_group', {group_id: activeGroup});
        if (data.success) { hideModal('groupInfoModal'); groups = groups.filter(g => g.id != activeGroup); activeGroup = null; renderChatList(); updateChatHeader(); document.getElementById('messages').innerHTML = ''; showToast('✅ Группа удалена'); }
    } catch {}
}

// === UTILS ===
function showImagePreview(src) { document.getElementById('previewImage').src = src; document.getElementById('imagePreviewModal').style.display = 'flex'; }
function downloadFile(path) { window.location.href = UPLOAD_DIR + path; }
function fmtSize(b) { if (!b) return ''; if (b < 1024) return b + ' B'; if (b < 1048576) return (b/1024).toFixed(1) + ' KB'; return (b/1048576).toFixed(1) + ' MB'; }
function formatDate(d) {
    const date = new Date(d), today = new Date(), yesterday = new Date(today);
    yesterday.setDate(today.getDate()-1);
    if (date.toDateString() === today.toDateString()) return 'Сегодня';
    if (date.toDateString() === yesterday.toDateString()) return 'Вчера';
    return date.toLocaleDateString('ru-RU', {day:'numeric',month:'long'});
}
function handleKeyPress(e) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    if (e.key === 'Escape') { document.getElementById('searchResults').style.display = 'none'; document.getElementById('emojiPicker').style.display = 'none'; }
}
function hideModal(id) { document.getElementById(id).style.display = 'none'; }
async function logout() {
    try { await api('logout'); } catch {}
    window.location.reload();
}
function escapeHtml(s) {
    if (s == null) return '';
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}
window.onclick = e => { if (e.target.classList.contains('modal')) e.target.style.display = 'none'; };
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
