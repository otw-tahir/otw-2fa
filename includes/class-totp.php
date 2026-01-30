<?php
/**
 * TOTP (Time-based One-Time Password) Class
 * 
 * Handles Google Authenticator compatible TOTP generation and verification.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class TOTP {
    
    /**
     * Base32 alphabet
     */
    private static $base32_alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    
    /**
     * Code length (6 digits)
     */
    private static $code_length = 6;
    
    /**
     * Time step (30 seconds)
     */
    private static $time_step = 30;
    
    /**
     * Generate a random secret key
     * 
     * @param int $length Secret length (default 16)
     * @return string Base32 encoded secret
     */
    public static function generate_secret($length = 16) {
        $secret = '';
        $alphabet_length = strlen(self::$base32_alphabet);
        
        for ($i = 0; $i < $length; $i++) {
            $secret .= self::$base32_alphabet[random_int(0, $alphabet_length - 1)];
        }
        
        return $secret;
    }
    
    /**
     * Generate TOTP code for given secret and time
     * 
     * @param string $secret Base32 encoded secret
     * @param int|null $timestamp Unix timestamp (null = current time)
     * @return string 6-digit code
     */
    public static function generate_code($secret, $timestamp = null) {
        if ($timestamp === null) {
            $timestamp = time();
        }
        
        // Calculate time counter
        $counter = floor($timestamp / self::$time_step);
        
        // Decode secret from base32
        $secret_bytes = self::base32_decode($secret);
        
        // Pack counter into 8 bytes
        $counter_bytes = pack('N*', 0, $counter);
        
        // Generate HMAC-SHA1
        $hash = hash_hmac('sha1', $counter_bytes, $secret_bytes, true);
        
        // Dynamic truncation
        $offset = ord($hash[strlen($hash) - 1]) & 0x0F;
        $code = (
            ((ord($hash[$offset]) & 0x7F) << 24) |
            ((ord($hash[$offset + 1]) & 0xFF) << 16) |
            ((ord($hash[$offset + 2]) & 0xFF) << 8) |
            (ord($hash[$offset + 3]) & 0xFF)
        ) % pow(10, self::$code_length);
        
        return str_pad($code, self::$code_length, '0', STR_PAD_LEFT);
    }
    
    /**
     * Verify TOTP code
     * 
     * @param string $secret Base32 encoded secret
     * @param string $code Code to verify
     * @param int $window Time window (number of periods to check before/after)
     * @return bool True if code is valid
     */
    public static function verify_code($secret, $code, $window = 1) {
        $code = preg_replace('/\s+/', '', $code);
        
        if (strlen($code) !== self::$code_length) {
            return false;
        }
        
        $timestamp = time();
        
        // Check codes within the time window
        for ($i = -$window; $i <= $window; $i++) {
            $check_time = $timestamp + ($i * self::$time_step);
            $expected_code = self::generate_code($secret, $check_time);
            
            if (hash_equals($expected_code, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate QR code URL for Google Authenticator
     * 
     * @param string $secret Base32 encoded secret
     * @param string $account_name User email or username
     * @param string $issuer Site name
     * @return string QR code URL (using Google Charts API)
     */
    public static function get_qr_code_url($secret, $account_name, $issuer = '') {
        if (empty($issuer)) {
            $issuer = get_bloginfo('name');
        }
        
        $issuer = rawurlencode($issuer);
        $account_name = rawurlencode($account_name);
        
        $otpauth_url = "otpauth://totp/{$issuer}:{$account_name}?secret={$secret}&issuer={$issuer}";
        
        // Return URL for QR code generation (using a free API)
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' . urlencode($otpauth_url);
    }
    
    /**
     * Get OTPAuth URL for manual entry
     * 
     * @param string $secret Base32 encoded secret
     * @param string $account_name User email or username
     * @param string $issuer Site name
     * @return string OTPAuth URL
     */
    public static function get_otpauth_url($secret, $account_name, $issuer = '') {
        if (empty($issuer)) {
            $issuer = get_bloginfo('name');
        }
        
        return "otpauth://totp/" . rawurlencode($issuer) . ":" . rawurlencode($account_name) . 
               "?secret={$secret}&issuer=" . rawurlencode($issuer);
    }
    
    /**
     * Decode base32 string to binary
     * 
     * @param string $input Base32 encoded string
     * @return string Binary data
     */
    private static function base32_decode($input) {
        $input = strtoupper($input);
        $input = str_replace(' ', '', $input);
        
        $output = '';
        $buffer = 0;
        $bits_in_buffer = 0;
        
        for ($i = 0; $i < strlen($input); $i++) {
            $char = $input[$i];
            $value = strpos(self::$base32_alphabet, $char);
            
            if ($value === false) {
                continue;
            }
            
            $buffer = ($buffer << 5) | $value;
            $bits_in_buffer += 5;
            
            if ($bits_in_buffer >= 8) {
                $bits_in_buffer -= 8;
                $output .= chr(($buffer >> $bits_in_buffer) & 0xFF);
            }
        }
        
        return $output;
    }
}
