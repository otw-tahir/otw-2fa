<?php
/**
 * Security Class
 * 
 * Handles rate limiting, failed attempts tracking, and IP blocking.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class Security {
    
    /**
     * Check if user is blocked due to failed attempts
     * 
     * @param int $user_id User ID
     * @return bool|int False if not blocked, or seconds remaining if blocked
     */
    public static function is_user_blocked($user_id) {
        $block_data = get_transient('otw_2fa_blocked_' . $user_id);
        
        if (!$block_data) {
            return false;
        }
        
        $block_until = $block_data['until'] ?? 0;
        
        if (time() < $block_until) {
            return $block_until - time();
        }
        
        // Block expired, clean up
        delete_transient('otw_2fa_blocked_' . $user_id);
        delete_transient('otw_2fa_attempts_' . $user_id);
        
        return false;
    }
    
    /**
     * Check if IP is blocked
     * 
     * @param string $ip IP address (optional, uses current if not provided)
     * @return bool|int False if not blocked, or seconds remaining if blocked
     */
    public static function is_ip_blocked($ip = null) {
        if ($ip === null) {
            $ip = self::get_client_ip();
        }
        
        $ip_hash = md5($ip);
        $block_data = get_transient('otw_2fa_ip_blocked_' . $ip_hash);
        
        if (!$block_data) {
            return false;
        }
        
        $block_until = $block_data['until'] ?? 0;
        
        if (time() < $block_until) {
            return $block_until - time();
        }
        
        // Block expired, clean up
        delete_transient('otw_2fa_ip_blocked_' . $ip_hash);
        delete_transient('otw_2fa_ip_attempts_' . $ip_hash);
        
        return false;
    }
    
    /**
     * Record a failed verification attempt
     * 
     * @param int $user_id User ID
     * @return array Status with blocked info
     */
    public static function record_failed_attempt($user_id) {
        $ip = self::get_client_ip();
        $ip_hash = md5($ip);
        
        $max_attempts = intval(get_option('otw_2fa_max_attempts', 5));
        $lockout_duration = intval(get_option('otw_2fa_lockout_duration', 5)) * 60; // Convert minutes to seconds
        $ip_block_duration = $lockout_duration * 3; // IP blocks last 3x longer
        $ip_max_attempts = $max_attempts * 2; // IP has 2x attempts allowed
        
        // Track user attempts
        $user_attempts = get_transient('otw_2fa_attempts_' . $user_id) ?: [];
        $user_attempts[] = time();
        
        // Keep only recent attempts (within lockout duration)
        $user_attempts = array_filter($user_attempts, function($time) use ($lockout_duration) {
            return $time > (time() - $lockout_duration);
        });
        
        set_transient('otw_2fa_attempts_' . $user_id, array_values($user_attempts), $lockout_duration);
        
        // Track IP attempts
        $ip_attempts = get_transient('otw_2fa_ip_attempts_' . $ip_hash) ?: [];
        $ip_attempts[] = time();
        
        // Keep only recent attempts
        $ip_attempts = array_filter($ip_attempts, function($time) use ($ip_block_duration) {
            return $time > (time() - $ip_block_duration);
        });
        
        set_transient('otw_2fa_ip_attempts_' . $ip_hash, array_values($ip_attempts), $ip_block_duration);
        
        $result = [
            'user_attempts' => count($user_attempts),
            'ip_attempts' => count($ip_attempts),
            'user_blocked' => false,
            'ip_blocked' => false,
            'user_remaining' => $max_attempts - count($user_attempts),
            'ip_remaining' => $ip_max_attempts - count($ip_attempts),
        ];
        
        // Block user if max attempts reached
        if (count($user_attempts) >= $max_attempts) {
            self::block_user($user_id, $lockout_duration);
            $result['user_blocked'] = true;
            $result['block_seconds'] = $lockout_duration;
            
            // Log the event
            do_action('otw_2fa_user_blocked', $user_id, $ip, count($user_attempts));
        }
        
        // Block IP if max attempts reached
        if (count($ip_attempts) >= $ip_max_attempts) {
            self::block_ip($ip, $ip_block_duration);
            $result['ip_blocked'] = true;
            $result['ip_block_seconds'] = $ip_block_duration;
            
            // Log the event
            do_action('otw_2fa_ip_blocked', $ip, count($ip_attempts));
        }
        
        return $result;
    }
    
    /**
     * Block a user for specified duration
     * 
     * @param int $user_id User ID
     * @param int $duration Duration in seconds
     */
    public static function block_user($user_id, $duration = 300) {
        set_transient('otw_2fa_blocked_' . $user_id, [
            'until' => time() + $duration,
            'reason' => 'too_many_attempts',
            'blocked_at' => time(),
        ], $duration);
    }
    
    /**
     * Block an IP for specified duration
     * 
     * @param string $ip IP address
     * @param int $duration Duration in seconds
     */
    public static function block_ip($ip, $duration = 900) {
        $ip_hash = md5($ip);
        set_transient('otw_2fa_ip_blocked_' . $ip_hash, [
            'until' => time() + $duration,
            'ip' => $ip,
            'reason' => 'too_many_attempts',
            'blocked_at' => time(),
        ], $duration);
    }
    
    /**
     * Clear failed attempts for a user (after successful login)
     * 
     * @param int $user_id User ID
     */
    public static function clear_user_attempts($user_id) {
        delete_transient('otw_2fa_attempts_' . $user_id);
        delete_transient('otw_2fa_blocked_' . $user_id);
    }
    
    /**
     * Record a successful verification attempt (clears failed attempts)
     * 
     * @param int $user_id User ID
     */
    public static function record_successful_attempt($user_id) {
        self::clear_user_attempts($user_id);
        self::clear_ip_attempts();
        
        // Log the event
        self::log_event('2fa_success', $user_id, [
            'ip' => self::get_client_ip(),
        ]);
    }
    
    /**
     * Clear failed attempts for an IP
     * 
     * @param string $ip IP address (optional)
     */
    public static function clear_ip_attempts($ip = null) {
        if ($ip === null) {
            $ip = self::get_client_ip();
        }
        $ip_hash = md5($ip);
        delete_transient('otw_2fa_ip_attempts_' . $ip_hash);
        delete_transient('otw_2fa_ip_blocked_' . $ip_hash);
    }
    
    /**
     * Get client IP address
     * 
     * @return string IP address
     */
    public static function get_client_ip() {
        $ip_keys = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR',
        ];
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                
                // Handle comma-separated IPs (X-Forwarded-For)
                if (strpos($ip, ',') !== false) {
                    $ips = explode(',', $ip);
                    $ip = trim($ips[0]);
                }
                
                // Validate IP
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return '0.0.0.0';
    }
    
    /**
     * Get remaining attempts for user
     * 
     * @param int $user_id User ID
     * @return int Remaining attempts
     */
    public static function get_remaining_attempts($user_id) {
        $max_attempts = get_option('otw_2fa_max_attempts', 5);
        $attempts = get_transient('otw_2fa_attempts_' . $user_id) ?: [];
        
        return max(0, $max_attempts - count($attempts));
    }
    
    /**
     * Log security event
     * 
     * @param string $event Event type
     * @param int $user_id User ID
     * @param array $data Additional data
     */
    public static function log_event($event, $user_id, $data = []) {
        if (!get_option('otw_2fa_enable_logging', 1)) {
            return;
        }
        
        $log_entry = [
            'event' => $event,
            'user_id' => $user_id,
            'ip' => self::get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
            'timestamp' => time(),
            'data' => $data,
        ];
        
        // Get existing log
        $log = get_option('otw_2fa_security_log', []);
        
        // Add new entry
        array_unshift($log, $log_entry);
        
        // Keep only last 1000 entries
        $log = array_slice($log, 0, 1000);
        
        update_option('otw_2fa_security_log', $log);
        
        // Allow external logging
        do_action('otw_2fa_security_event', $event, $user_id, $log_entry);
    }
    
    /**
     * Get security log
     * 
     * @param int $limit Number of entries
     * @param string $event_filter Filter by event type
     * @return array Log entries
     */
    public static function get_log($limit = 100, $event_filter = '') {
        $log = get_option('otw_2fa_security_log', []);
        
        if (!empty($event_filter)) {
            $log = array_filter($log, function($entry) use ($event_filter) {
                return $entry['event'] === $event_filter;
            });
        }
        
        return array_slice($log, 0, $limit);
    }
    
    /**
     * Clear security log
     */
    public static function clear_log() {
        delete_option('otw_2fa_security_log');
    }
    
    /**
     * Get formatted block time
     * 
     * @param int $seconds Seconds
     * @return string Formatted time (e.g., "5 minutes")
     */
    public static function format_block_time($seconds) {
        if ($seconds < 60) {
            return sprintf(_n('%d second', '%d seconds', $seconds, 'otw-2fa'), $seconds);
        }
        
        $minutes = ceil($seconds / 60);
        return sprintf(_n('%d minute', '%d minutes', $minutes, 'otw-2fa'), $minutes);
    }
}
