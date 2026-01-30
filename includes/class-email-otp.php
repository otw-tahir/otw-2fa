<?php
/**
 * Email OTP Class
 * 
 * Handles email-based one-time password generation and verification.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class Email_OTP {
    
    /**
     * Generate and send OTP via email
     * 
     * @param int $user_id User ID
     * @return bool True if sent successfully
     */
    public static function send_code($user_id) {
        $user = get_userdata($user_id);
        
        if (!$user || !$user->user_email) {
            return false;
        }
        
        // Generate code
        $code_length = get_option('otw_2fa_code_length', 6);
        $code = self::generate_code($code_length);
        
        // Store code with expiry
        $expiry = get_option('otw_2fa_code_expiry', 300);
        set_transient('otw_2fa_email_code_' . $user_id, [
            'code' => wp_hash($code),
            'created' => time(),
        ], $expiry);
        
        // Prepare email
        $site_name = get_bloginfo('name');
        $subject = sprintf(__('[%s] Your verification code', 'otw-2fa'), $site_name);
        
        $message = sprintf(
            __("Hello %s,\n\nYour verification code is: %s\n\nThis code will expire in %d minutes.\n\nIf you did not request this code, please ignore this email.\n\nBest regards,\n%s", 'otw-2fa'),
            $user->display_name,
            $code,
            ceil($expiry / 60),
            $site_name
        );
        
        $headers = ['Content-Type: text/plain; charset=UTF-8'];
        
        // Send email
        $sent = wp_mail($user->user_email, $subject, $message, $headers);
        
        if ($sent) {
            // Log for debugging
            do_action('otw_2fa_email_sent', $user_id, $user->user_email);
        }
        
        return $sent;
    }
    
    /**
     * Verify email OTP code
     * 
     * @param int $user_id User ID
     * @param string $code Code to verify
     * @return bool True if code is valid
     */
    public static function verify_code($user_id, $code) {
        $code = preg_replace('/\s+/', '', $code);
        
        $stored = get_transient('otw_2fa_email_code_' . $user_id);
        
        if (!$stored || !isset($stored['code'])) {
            return false;
        }
        
        // Check if code matches
        if (wp_check_password($code, $stored['code'])) {
            // Delete the code after successful verification
            delete_transient('otw_2fa_email_code_' . $user_id);
            return true;
        }
        
        return false;
    }
    
    /**
     * Generate random numeric code
     * 
     * @param int $length Code length
     * @return string Numeric code
     */
    private static function generate_code($length = 6) {
        $code = '';
        for ($i = 0; $i < $length; $i++) {
            $code .= random_int(0, 9);
        }
        return $code;
    }
    
    /**
     * Check if a code is pending for user
     * 
     * @param int $user_id User ID
     * @return bool True if code exists and hasn't expired
     */
    public static function has_pending_code($user_id) {
        return get_transient('otw_2fa_email_code_' . $user_id) !== false;
    }
    
    /**
     * Get masked email for display
     * 
     * @param string $email Email address
     * @return string Masked email (e.g., u***@g***.com)
     */
    public static function mask_email($email) {
        $parts = explode('@', $email);
        
        if (count($parts) !== 2) {
            return $email;
        }
        
        $local = $parts[0];
        $domain = $parts[1];
        
        // Mask local part
        $local_masked = substr($local, 0, 1) . str_repeat('*', max(1, strlen($local) - 1));
        
        // Mask domain
        $domain_parts = explode('.', $domain);
        $domain_masked = substr($domain_parts[0], 0, 1) . str_repeat('*', max(1, strlen($domain_parts[0]) - 1));
        
        if (count($domain_parts) > 1) {
            $domain_masked .= '.' . end($domain_parts);
        }
        
        return $local_masked . '@' . $domain_masked;
    }
}
