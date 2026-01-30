<?php
/**
 * SMS OTP Class
 * 
 * Handles SMS-based one-time password generation and verification.
 * Supports Twilio and custom webhook providers.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class SMS_OTP {
    
    /**
     * Generate and send OTP via SMS
     * 
     * @param int $user_id User ID
     * @return bool|WP_Error True if sent successfully, WP_Error on failure
     */
    public static function send_code($user_id) {
        $phone = get_user_meta($user_id, 'otw_2fa_phone', true);
        
        if (empty($phone)) {
            return new \WP_Error('no_phone', __('No phone number configured for this user.', 'otw-2fa'));
        }
        
        // Generate code
        $code_length = get_option('otw_2fa_code_length', 6);
        $code = self::generate_code($code_length);
        
        // Store code with expiry
        $expiry = get_option('otw_2fa_code_expiry', 300);
        set_transient('otw_2fa_sms_code_' . $user_id, [
            'code' => wp_hash($code),
            'created' => time(),
        ], $expiry);
        
        // Prepare message
        $site_name = get_bloginfo('name');
        $message = sprintf(
            __('%s: Your verification code is %s. It expires in %d minutes.', 'otw-2fa'),
            $site_name,
            $code,
            ceil($expiry / 60)
        );
        
        // Send via configured provider
        $provider = get_option('otw_2fa_sms_provider', 'twilio');
        
        switch ($provider) {
            case 'twilio':
                $result = self::send_via_twilio($phone, $message);
                break;
            case 'webhook':
                $result = self::send_via_webhook($phone, $message, $code);
                break;
            default:
                $result = apply_filters('otw_2fa_send_sms', false, $phone, $message, $code);
        }
        
        if ($result === true) {
            do_action('otw_2fa_sms_sent', $user_id, $phone);
        }
        
        return $result;
    }
    
    /**
     * Send SMS via Twilio
     * 
     * @param string $phone Phone number
     * @param string $message Message to send
     * @return bool|WP_Error
     */
    private static function send_via_twilio($phone, $message) {
        $account_sid = get_option('otw_2fa_twilio_sid');
        $auth_token = get_option('otw_2fa_twilio_token');
        $from_phone = get_option('otw_2fa_twilio_phone');
        
        if (empty($account_sid) || empty($auth_token) || empty($from_phone)) {
            return new \WP_Error('twilio_not_configured', __('Twilio is not properly configured.', 'otw-2fa'));
        }
        
        $url = "https://api.twilio.com/2010-04-01/Accounts/{$account_sid}/Messages.json";
        
        $response = wp_remote_post($url, [
            'headers' => [
                'Authorization' => 'Basic ' . base64_encode("{$account_sid}:{$auth_token}"),
            ],
            'body' => [
                'From' => $from_phone,
                'To' => $phone,
                'Body' => $message,
            ],
            'timeout' => 30,
        ]);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        
        if ($status_code >= 200 && $status_code < 300) {
            return true;
        }
        
        $body = json_decode(wp_remote_retrieve_body($response), true);
        $error_message = isset($body['message']) ? $body['message'] : __('Failed to send SMS.', 'otw-2fa');
        
        return new \WP_Error('twilio_error', $error_message);
    }
    
    /**
     * Send SMS via custom webhook
     * 
     * @param string $phone Phone number
     * @param string $message Message to send
     * @param string $code The OTP code
     * @return bool|WP_Error
     */
    private static function send_via_webhook($phone, $message, $code) {
        $webhook_url = get_option('otw_2fa_webhook_url');
        
        if (empty($webhook_url)) {
            return new \WP_Error('webhook_not_configured', __('Webhook URL is not configured.', 'otw-2fa'));
        }
        
        $response = wp_remote_post($webhook_url, [
            'headers' => [
                'Content-Type' => 'application/json',
            ],
            'body' => wp_json_encode([
                'phone' => $phone,
                'message' => $message,
                'code' => $code,
                'site' => get_bloginfo('name'),
                'site_url' => home_url(),
            ]),
            'timeout' => 30,
        ]);
        
        if (is_wp_error($response)) {
            return $response;
        }
        
        $status_code = wp_remote_retrieve_response_code($response);
        
        return $status_code >= 200 && $status_code < 300;
    }
    
    /**
     * Verify SMS OTP code
     * 
     * @param int $user_id User ID
     * @param string $code Code to verify
     * @return bool True if code is valid
     */
    public static function verify_code($user_id, $code) {
        $code = preg_replace('/\s+/', '', $code);
        
        $stored = get_transient('otw_2fa_sms_code_' . $user_id);
        
        if (!$stored || !isset($stored['code'])) {
            return false;
        }
        
        // Check if code matches
        if (wp_check_password($code, $stored['code'])) {
            // Delete the code after successful verification
            delete_transient('otw_2fa_sms_code_' . $user_id);
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
        return get_transient('otw_2fa_sms_code_' . $user_id) !== false;
    }
    
    /**
     * Get masked phone for display
     * 
     * @param string $phone Phone number
     * @return string Masked phone (e.g., ***-***-1234)
     */
    public static function mask_phone($phone) {
        $digits = preg_replace('/[^0-9]/', '', $phone);
        $length = strlen($digits);
        
        if ($length <= 4) {
            return $phone;
        }
        
        $visible = substr($digits, -4);
        $masked = str_repeat('*', $length - 4);
        
        return $masked . $visible;
    }
    
    /**
     * Validate phone number format
     * 
     * @param string $phone Phone number
     * @return bool True if valid
     */
    public static function validate_phone($phone) {
        // Remove all non-digit characters except +
        $cleaned = preg_replace('/[^0-9+]/', '', $phone);
        
        // Must have at least 10 digits
        $digits = preg_replace('/[^0-9]/', '', $cleaned);
        
        return strlen($digits) >= 10 && strlen($digits) <= 15;
    }
}
