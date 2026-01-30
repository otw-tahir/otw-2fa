<?php
/**
 * Plugin Name: OTW 2FA
 * Plugin URI: https://developer.starter.dev/
 * Description: Two-Factor Authentication for WordPress with Google Authenticator, Email, and SMS options.
 * Version: 1.0.0
 * Author: Developer Starter
 * Author URI: https://developer.starter.dev/
 * Text Domain: otw-2fa
 * License: GPL2
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

// Plugin constants
define('OTW_2FA_VERSION', '1.0.0');
define('OTW_2FA_PLUGIN_FILE', __FILE__);
define('OTW_2FA_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('OTW_2FA_PLUGIN_URL', plugin_dir_url(__FILE__));

/**
 * Main Plugin Class
 */
class Plugin {
    
    /**
     * Singleton instance
     */
    private static $instance = null;
    
    /**
     * Get singleton instance
     */
    public static function instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    /**
     * Constructor
     */
    private function __construct() {
        $this->load_dependencies();
        $this->init_hooks();
    }
    
    /**
     * Load required files
     */
    private function load_dependencies() {
        require_once OTW_2FA_PLUGIN_DIR . 'includes/class-totp.php';
        require_once OTW_2FA_PLUGIN_DIR . 'includes/class-email-otp.php';
        require_once OTW_2FA_PLUGIN_DIR . 'includes/class-sms-otp.php';
        require_once OTW_2FA_PLUGIN_DIR . 'includes/class-user-settings.php';
        require_once OTW_2FA_PLUGIN_DIR . 'includes/class-login-handler.php';
        require_once OTW_2FA_PLUGIN_DIR . 'includes/class-admin.php';
    }
    
    /**
     * Initialize hooks
     */
    private function init_hooks() {
        add_action('init', [$this, 'load_textdomain']);
        
        // Initialize components
        new User_Settings();
        new Login_Handler();
        new Admin();
    }
    
    /**
     * Load plugin textdomain
     */
    public function load_textdomain() {
        load_plugin_textdomain('otw-2fa', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }
    
    /**
     * Activation hook
     */
    public static function activate() {
        // Default options
        add_option('otw_2fa_enable_totp', 1);
        add_option('otw_2fa_enable_email', 1);
        add_option('otw_2fa_enable_sms', 0);
        add_option('otw_2fa_sms_provider', 'twilio');
        add_option('otw_2fa_twilio_sid', '');
        add_option('otw_2fa_twilio_token', '');
        add_option('otw_2fa_twilio_phone', '');
        add_option('otw_2fa_code_expiry', 300); // 5 minutes
        add_option('otw_2fa_code_length', 6);
        add_option('otw_2fa_required_roles', ['administrator']);
    }
    
    /**
     * Deactivation hook
     */
    public static function deactivate() {
        // Clean up transients
        global $wpdb;
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_otw_2fa_%'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_timeout_otw_2fa_%'");
    }
}

// Activation/Deactivation hooks
register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [Plugin::class, 'deactivate']);

/**
 * Get plugin instance
 */
function otw_2fa() {
    return Plugin::instance();
}

// Initialize plugin
add_action('plugins_loaded', 'OTW\\TwoFA\\otw_2fa');
