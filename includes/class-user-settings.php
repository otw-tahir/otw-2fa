<?php
/**
 * User Settings Class
 * 
 * Handles user 2FA preferences and settings in profile page.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class User_Settings {
    
    /**
     * Constructor
     */
    public function __construct() {
        // Add 2FA settings to user profile
        add_action('show_user_profile', [$this, 'render_user_settings']);
        add_action('edit_user_profile', [$this, 'render_user_settings']);
        
        // Save user settings
        add_action('personal_options_update', [$this, 'save_user_settings']);
        add_action('edit_user_profile_update', [$this, 'save_user_settings']);
        
        // AJAX handlers
        add_action('wp_ajax_otw_2fa_generate_secret', [$this, 'ajax_generate_secret']);
        add_action('wp_ajax_otw_2fa_verify_setup', [$this, 'ajax_verify_setup']);
        add_action('wp_ajax_otw_2fa_send_test_email', [$this, 'ajax_send_test_email']);
        add_action('wp_ajax_otw_2fa_send_test_sms', [$this, 'ajax_send_test_sms']);
        add_action('wp_ajax_otw_2fa_send_test_whatsapp', [$this, 'ajax_send_test_whatsapp']);
        add_action('wp_ajax_otw_2fa_disable', [$this, 'ajax_disable_2fa']);
        
        // Enqueue scripts
        add_action('admin_enqueue_scripts', [$this, 'enqueue_scripts']);
    }
    
    /**
     * Enqueue scripts for user profile page
     */
    public function enqueue_scripts($hook) {
        if (!in_array($hook, ['profile.php', 'user-edit.php'])) {
            return;
        }
        
        wp_enqueue_style(
            'otw-2fa-user',
            OTW_2FA_PLUGIN_URL . 'assets/css/user-settings.css',
            [],
            OTW_2FA_VERSION
        );
        
        wp_enqueue_script(
            'otw-2fa-user',
            OTW_2FA_PLUGIN_URL . 'assets/js/user-settings.js',
            ['jquery'],
            OTW_2FA_VERSION,
            true
        );
        
        wp_localize_script('otw-2fa-user', 'otw2fa', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('otw_2fa_nonce'),
            'strings' => [
                'generating' => __('Generating...', 'otw-2fa'),
                'verifying' => __('Verifying...', 'otw-2fa'),
                'sending' => __('Sending...', 'otw-2fa'),
                'success' => __('Success!', 'otw-2fa'),
                'error' => __('An error occurred.', 'otw-2fa'),
                'codeSent' => __('Code sent! Check your inbox.', 'otw-2fa'),
                'smsSent' => __('SMS sent! Check your phone.', 'otw-2fa'),
                'whatsappSent' => __('WhatsApp message sent! Check your phone.', 'otw-2fa'),
                'verified' => __('2FA has been enabled!', 'otw-2fa'),
                'disabled' => __('2FA has been disabled.', 'otw-2fa'),
                'invalidCode' => __('Invalid verification code.', 'otw-2fa'),
                'confirmDisable' => __('Are you sure you want to disable 2FA?', 'otw-2fa'),
            ],
        ]);
    }
    
    /**
     * Render 2FA settings in user profile
     */
    public function render_user_settings($user) {
        // Check if current user can edit this profile
        if (!current_user_can('edit_user', $user->ID)) {
            return;
        }
        
        $enabled_methods = self::get_methods($user->ID);
        $is_enabled = !empty($enabled_methods);
        $totp_secret = get_user_meta($user->ID, 'otw_2fa_totp_secret', true);
        $phone = get_user_meta($user->ID, 'otw_2fa_phone', true);
        $whatsapp = get_user_meta($user->ID, 'otw_2fa_whatsapp', true);
        
        $enable_totp = get_option('otw_2fa_enable_totp', 1);
        $enable_email = get_option('otw_2fa_enable_email', 1);
        $enable_sms = get_option('otw_2fa_enable_sms', 0);
        $enable_whatsapp = get_option('otw_2fa_enable_whatsapp', 0);
        
        ?>
        <h2><?php _e('Two-Factor Authentication', 'otw-2fa'); ?></h2>
        <table class="form-table otw-2fa-settings" role="presentation">
            <tr>
                <th scope="row"><?php _e('2FA Status', 'otw-2fa'); ?></th>
                <td>
                    <?php if ($is_enabled): ?>
                        <span class="otw-2fa-status otw-2fa-status-enabled">
                            <?php _e('Enabled', 'otw-2fa'); ?>
                            (<?php echo esc_html($this->get_methods_label($enabled_methods)); ?>)
                        </span>
                        <button type="button" class="button button-secondary otw-2fa-disable-btn" data-user-id="<?php echo esc_attr($user->ID); ?>">
                            <?php _e('Disable 2FA', 'otw-2fa'); ?>
                        </button>
                    <?php else: ?>
                        <span class="otw-2fa-status otw-2fa-status-disabled">
                            <?php _e('Not Enabled', 'otw-2fa'); ?>
                        </span>
                    <?php endif; ?>
                </td>
            </tr>
            
            <?php if (!$is_enabled): ?>
            <tr>
                <th scope="row"><?php _e('Choose Methods', 'otw-2fa'); ?></th>
                <td>
                    <fieldset>
                        <p class="description" style="margin-bottom: 10px;">
                            <?php _e('Select one or more 2FA methods. You can use any enabled method during login.', 'otw-2fa'); ?>
                        </p>
                        <?php if ($enable_totp): ?>
                        <label>
                            <input type="checkbox" name="otw_2fa_setup_methods[]" value="totp" class="otw-2fa-method-checkbox">
                            <?php _e('Google Authenticator / TOTP App', 'otw-2fa'); ?>
                        </label><br>
                        <?php endif; ?>
                        
                        <?php if ($enable_email): ?>
                        <label>
                            <input type="checkbox" name="otw_2fa_setup_methods[]" value="email" class="otw-2fa-method-checkbox">
                            <?php _e('Email Verification Code', 'otw-2fa'); ?>
                            <span class="description">(<?php echo esc_html(Email_OTP::mask_email($user->user_email)); ?>)</span>
                        </label><br>
                        <?php endif; ?>
                        
                        <?php if ($enable_sms): ?>
                        <label>
                            <input type="checkbox" name="otw_2fa_setup_methods[]" value="sms" class="otw-2fa-method-checkbox">
                            <?php _e('SMS Verification Code', 'otw-2fa'); ?>
                        </label><br>
                        <?php endif; ?>
                        
                        <?php if ($enable_whatsapp): ?>
                        <label>
                            <input type="checkbox" name="otw_2fa_setup_methods[]" value="whatsapp" class="otw-2fa-method-checkbox">
                            <?php _e('WhatsApp Verification Code', 'otw-2fa'); ?>
                        </label>
                        <?php endif; ?>
                    </fieldset>
                </td>
            </tr>
            
            <!-- TOTP Setup Section -->
            <?php if ($enable_totp): ?>
            <tr class="otw-2fa-setup-section otw-2fa-setup-totp">
                <th scope="row"><?php _e('Setup Authenticator', 'otw-2fa'); ?></th>
                <td>
                    <div class="otw-2fa-totp-setup">
                        <button type="button" class="button button-primary" id="otw-2fa-generate-secret">
                            <?php _e('Generate New Secret', 'otw-2fa'); ?>
                        </button>
                        
                        <div class="otw-2fa-qr-container" style="display: none;">
                            <p><?php _e('Scan this QR code with your authenticator app:', 'otw-2fa'); ?></p>
                            <img id="otw-2fa-qr-code" src="" alt="QR Code">
                            
                            <p><?php _e('Or enter this code manually:', 'otw-2fa'); ?></p>
                            <code id="otw-2fa-secret-display"></code>
                            
                            <input type="hidden" id="otw-2fa-secret" name="otw_2fa_totp_secret">
                            
                            <p><?php _e('Enter the code from your app to verify:', 'otw-2fa'); ?></p>
                            <input type="text" id="otw-2fa-verify-code" class="regular-text" placeholder="123456" maxlength="6" autocomplete="off">
                            <button type="button" class="button" id="otw-2fa-verify-totp">
                                <?php _e('Verify & Enable', 'otw-2fa'); ?>
                            </button>
                            <span class="otw-2fa-message"></span>
                        </div>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
            
            <!-- Email Setup Section -->
            <?php if ($enable_email): ?>
            <tr class="otw-2fa-setup-section otw-2fa-setup-email" style="display: none;">
                <th scope="row"><?php _e('Setup Email 2FA', 'otw-2fa'); ?></th>
                <td>
                    <div class="otw-2fa-email-setup">
                        <p>
                            <?php printf(
                                __('Verification codes will be sent to: %s', 'otw-2fa'),
                                '<strong>' . esc_html($user->user_email) . '</strong>'
                            ); ?>
                        </p>
                        
                        <button type="button" class="button button-primary" id="otw-2fa-send-test-email">
                            <?php _e('Send Test Code', 'otw-2fa'); ?>
                        </button>
                        
                        <div class="otw-2fa-email-verify" style="display: none;">
                            <p><?php _e('Enter the code from your email:', 'otw-2fa'); ?></p>
                            <input type="text" id="otw-2fa-email-code" class="regular-text" placeholder="123456" maxlength="6" autocomplete="off">
                            <button type="button" class="button" id="otw-2fa-verify-email">
                                <?php _e('Verify & Enable', 'otw-2fa'); ?>
                            </button>
                            <span class="otw-2fa-message"></span>
                        </div>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
            
            <!-- SMS Setup Section -->
            <?php if ($enable_sms): ?>
            <tr class="otw-2fa-setup-section otw-2fa-setup-sms" style="display: none;">
                <th scope="row"><?php _e('Setup SMS 2FA', 'otw-2fa'); ?></th>
                <td>
                    <div class="otw-2fa-sms-setup">
                        <p>
                            <label for="otw-2fa-phone"><?php _e('Phone Number:', 'otw-2fa'); ?></label><br>
                            <input type="tel" id="otw-2fa-phone" name="otw_2fa_phone" class="regular-text" 
                                   value="<?php echo esc_attr($phone); ?>" 
                                   placeholder="+1234567890">
                            <p class="description"><?php _e('Include country code (e.g., +1 for US)', 'otw-2fa'); ?></p>
                        </p>
                        
                        <button type="button" class="button button-primary" id="otw-2fa-send-test-sms">
                            <?php _e('Send Test Code', 'otw-2fa'); ?>
                        </button>
                        
                        <div class="otw-2fa-sms-verify" style="display: none;">
                            <p><?php _e('Enter the code from your SMS:', 'otw-2fa'); ?></p>
                            <input type="text" id="otw-2fa-sms-code" class="regular-text" placeholder="123456" maxlength="6" autocomplete="off">
                            <button type="button" class="button" id="otw-2fa-verify-sms">
                                <?php _e('Verify & Enable', 'otw-2fa'); ?>
                            </button>
                            <span class="otw-2fa-message"></span>
                        </div>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
            
            <!-- WhatsApp Setup Section -->
            <?php if ($enable_whatsapp): ?>
            <tr class="otw-2fa-setup-section otw-2fa-setup-whatsapp" style="display: none;">
                <th scope="row"><?php _e('Setup WhatsApp 2FA', 'otw-2fa'); ?></th>
                <td>
                    <div class="otw-2fa-whatsapp-setup">
                        <p>
                            <label for="otw-2fa-whatsapp"><?php _e('WhatsApp Number:', 'otw-2fa'); ?></label><br>
                            <input type="tel" id="otw-2fa-whatsapp" name="otw_2fa_whatsapp" class="regular-text" 
                                   value="<?php echo esc_attr($whatsapp); ?>" 
                                   placeholder="+1234567890">
                            <p class="description"><?php _e('Include country code (e.g., +1 for US)', 'otw-2fa'); ?></p>
                        </p>
                        
                        <button type="button" class="button button-primary" id="otw-2fa-send-test-whatsapp">
                            <?php _e('Send Test Code', 'otw-2fa'); ?>
                        </button>
                        
                        <div class="otw-2fa-whatsapp-verify" style="display: none;">
                            <p><?php _e('Enter the code from your WhatsApp:', 'otw-2fa'); ?></p>
                            <input type="text" id="otw-2fa-whatsapp-code" class="regular-text" placeholder="123456" maxlength="6" autocomplete="off">
                            <button type="button" class="button" id="otw-2fa-verify-whatsapp">
                                <?php _e('Verify & Enable', 'otw-2fa'); ?>
                            </button>
                            <span class="otw-2fa-message"></span>
                        </div>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
            
            <?php endif; // End !$is_enabled ?>
            
            <!-- Backup Codes -->
            <?php if ($is_enabled): ?>
            <tr>
                <th scope="row"><?php _e('Backup Codes', 'otw-2fa'); ?></th>
                <td>
                    <?php
                    $backup_codes = get_user_meta($user->ID, 'otw_2fa_backup_codes', true);
                    $remaining = is_array($backup_codes) ? count($backup_codes) : 0;
                    ?>
                    <p>
                        <?php printf(__('You have %d backup codes remaining.', 'otw-2fa'), $remaining); ?>
                    </p>
                    <button type="button" class="button" id="otw-2fa-generate-backup-codes">
                        <?php _e('Generate New Backup Codes', 'otw-2fa'); ?>
                    </button>
                    <div id="otw-2fa-backup-codes-display" style="display: none;"></div>
                </td>
            </tr>
            <?php endif; ?>
        </table>
        
        <input type="hidden" name="otw_2fa_user_id" value="<?php echo esc_attr($user->ID); ?>">
        <?php
    }
    
    /**
     * Get human-readable method label
     */
    private function get_method_label($method) {
        $labels = [
            'totp' => __('Google Authenticator', 'otw-2fa'),
            'email' => __('Email', 'otw-2fa'),
            'sms' => __('SMS', 'otw-2fa'),
            'whatsapp' => __('WhatsApp', 'otw-2fa'),
        ];
        
        return $labels[$method] ?? $method;
    }
    
    /**
     * Get human-readable labels for multiple methods
     */
    private function get_methods_label($methods) {
        if (!is_array($methods)) {
            return $this->get_method_label($methods);
        }
        
        $labels = [];
        foreach ($methods as $method) {
            $labels[] = $this->get_method_label($method);
        }
        
        return implode(', ', $labels);
    }
    
    /**
     * Save user settings
     */
    public function save_user_settings($user_id) {
        if (!current_user_can('edit_user', $user_id)) {
            return;
        }
        
        // Phone number update (for SMS)
        if (isset($_POST['otw_2fa_phone'])) {
            $phone = sanitize_text_field($_POST['otw_2fa_phone']);
            update_user_meta($user_id, 'otw_2fa_phone', $phone);
        }
    }
    
    /**
     * AJAX: Generate new TOTP secret
     */
    public function ajax_generate_secret() {
        check_ajax_referer('otw_2fa_nonce', 'nonce');
        
        $user_id = get_current_user_id();
        $user = get_userdata($user_id);
        
        if (!$user) {
            wp_send_json_error(['message' => __('Invalid user.', 'otw-2fa')]);
        }
        
        $secret = TOTP::generate_secret();
        $qr_url = TOTP::get_qr_code_url($secret, $user->user_email);
        
        // Store temporarily (not saved until verified)
        set_transient('otw_2fa_pending_secret_' . $user_id, $secret, 600);
        
        wp_send_json_success([
            'secret' => $secret,
            'qr_url' => $qr_url,
        ]);
    }
    
    /**
     * AJAX: Verify TOTP setup and enable
     */
    public function ajax_verify_setup() {
        check_ajax_referer('otw_2fa_nonce', 'nonce');
        
        $user_id = get_current_user_id();
        $code = sanitize_text_field($_POST['code'] ?? '');
        $method = sanitize_text_field($_POST['method'] ?? 'totp');
        
        if (empty($code)) {
            wp_send_json_error(['message' => __('Please enter a verification code.', 'otw-2fa')]);
        }
        
        $verified = false;
        
        switch ($method) {
            case 'totp':
                $secret = get_transient('otw_2fa_pending_secret_' . $user_id);
                if (!$secret) {
                    wp_send_json_error(['message' => __('Secret expired. Please generate a new one.', 'otw-2fa')]);
                }
                $verified = TOTP::verify_code($secret, $code);
                if ($verified) {
                    update_user_meta($user_id, 'otw_2fa_totp_secret', $secret);
                    delete_transient('otw_2fa_pending_secret_' . $user_id);
                }
                break;
                
            case 'email':
                $verified = Email_OTP::verify_code($user_id, $code);
                break;
                
            case 'sms':
                $verified = SMS_OTP::verify_code($user_id, $code);
                break;
                
            case 'whatsapp':
                $verified = WhatsApp_OTP::verify_code($user_id, $code);
                break;
        }
        
        if ($verified) {
            // Add this method to user's enabled methods
            $enabled_methods = self::add_method($user_id, $method);
            
            // Generate backup codes if this is the first method
            $backup_codes = null;
            if (count($enabled_methods) === 1) {
                $backup_codes = $this->generate_backup_codes($user_id);
            }
            
            wp_send_json_success([
                'message' => sprintf(
                    __('%s has been enabled! You can now add more methods or reload to see your settings.', 'otw-2fa'),
                    $this->get_method_label($method)
                ),
                'backup_codes' => $backup_codes,
                'enabled_methods' => $enabled_methods,
            ]);
        } else {
            wp_send_json_error(['message' => __('Invalid verification code.', 'otw-2fa')]);
        }
    }
    
    /**
     * AJAX: Send test email code
     */
    public function ajax_send_test_email() {
        check_ajax_referer('otw_2fa_nonce', 'nonce');
        
        $user_id = get_current_user_id();
        $sent = Email_OTP::send_code($user_id);
        
        if ($sent) {
            wp_send_json_success(['message' => __('Verification code sent!', 'otw-2fa')]);
        } else {
            wp_send_json_error(['message' => __('Failed to send email.', 'otw-2fa')]);
        }
    }
    
    /**
     * AJAX: Send test SMS code
     */
    public function ajax_send_test_sms() {
        check_ajax_referer('otw_2fa_nonce', 'nonce');
        
        $user_id = get_current_user_id();
        $phone = sanitize_text_field($_POST['phone'] ?? '');
        
        if (empty($phone)) {
            wp_send_json_error(['message' => __('Please enter a phone number.', 'otw-2fa')]);
        }
        
        if (!SMS_OTP::validate_phone($phone)) {
            wp_send_json_error(['message' => __('Invalid phone number format.', 'otw-2fa')]);
        }
        
        // Save phone number
        update_user_meta($user_id, 'otw_2fa_phone', $phone);
        
        $result = SMS_OTP::send_code($user_id);
        
        if ($result === true) {
            wp_send_json_success(['message' => __('Verification code sent!', 'otw-2fa')]);
        } elseif (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        } else {
            wp_send_json_error(['message' => __('Failed to send SMS.', 'otw-2fa')]);
        }
    }
    
    /**
     * AJAX: Send test WhatsApp code
     */
    public function ajax_send_test_whatsapp() {
        check_ajax_referer('otw_2fa_nonce', 'nonce');
        
        $user_id = get_current_user_id();
        $whatsapp = sanitize_text_field($_POST['whatsapp'] ?? '');
        
        if (empty($whatsapp)) {
            wp_send_json_error(['message' => __('Please enter a WhatsApp number.', 'otw-2fa')]);
        }
        
        if (!WhatsApp_OTP::validate_phone($whatsapp)) {
            wp_send_json_error(['message' => __('Invalid WhatsApp number format.', 'otw-2fa')]);
        }
        
        // Save WhatsApp number
        update_user_meta($user_id, 'otw_2fa_whatsapp', $whatsapp);
        
        $result = WhatsApp_OTP::send_code($user_id);
        
        if ($result === true) {
            wp_send_json_success(['message' => __('Verification code sent!', 'otw-2fa')]);
        } elseif (is_wp_error($result)) {
            wp_send_json_error(['message' => $result->get_error_message()]);
        } else {
            wp_send_json_error(['message' => __('Failed to send WhatsApp message.', 'otw-2fa')]);
        }
    }
    
    /**
     * AJAX: Disable 2FA
     */
    public function ajax_disable_2fa() {
        check_ajax_referer('otw_2fa_nonce', 'nonce');
        
        $user_id = intval($_POST['user_id'] ?? 0);
        
        // Check permissions
        if ($user_id !== get_current_user_id() && !current_user_can('edit_user', $user_id)) {
            wp_send_json_error(['message' => __('Permission denied.', 'otw-2fa')]);
        }
        
        // Remove 2FA settings
        delete_user_meta($user_id, 'otw_2fa_method');
        delete_user_meta($user_id, 'otw_2fa_methods');
        delete_user_meta($user_id, 'otw_2fa_totp_secret');
        delete_user_meta($user_id, 'otw_2fa_backup_codes');
        
        wp_send_json_success(['message' => __('2FA has been disabled.', 'otw-2fa')]);
    }
    
    /**
     * Generate backup codes for user
     */
    private function generate_backup_codes($user_id, $count = 10) {
        $codes = [];
        
        for ($i = 0; $i < $count; $i++) {
            $code = strtoupper(wp_generate_password(8, false));
            $codes[] = $code;
        }
        
        // Store hashed codes
        $hashed_codes = array_map(function($code) {
            return hash('sha256', $code);
        }, $codes);
        
        update_user_meta($user_id, 'otw_2fa_backup_codes', $hashed_codes);
        
        return $codes; // Return plain codes for display
    }
    
    /**
     * Check if 2FA is enabled for user
     */
    public static function is_enabled($user_id) {
        $methods = self::get_methods($user_id);
        return !empty($methods);
    }
    
    /**
     * Get user's 2FA method (returns first method for backward compatibility)
     * @deprecated Use get_methods() instead
     */
    public static function get_method($user_id) {
        $methods = self::get_methods($user_id);
        return !empty($methods) ? $methods[0] : '';
    }
    
    /**
     * Get user's enabled 2FA methods (array)
     */
    public static function get_methods($user_id) {
        $methods = get_user_meta($user_id, 'otw_2fa_methods', true);
        
        // Backward compatibility: check old single method field
        if (empty($methods)) {
            $old_method = get_user_meta($user_id, 'otw_2fa_method', true);
            if (!empty($old_method) && $old_method !== 'none') {
                return [$old_method];
            }
            return [];
        }
        
        return is_array($methods) ? $methods : [$methods];
    }
    
    /**
     * Check if user has a specific method enabled
     */
    public static function has_method($user_id, $method) {
        $methods = self::get_methods($user_id);
        return in_array($method, $methods);
    }
    
    /**
     * Add a method to user's enabled methods
     */
    public static function add_method($user_id, $method) {
        $methods = self::get_methods($user_id);
        
        if (!in_array($method, $methods)) {
            $methods[] = $method;
            update_user_meta($user_id, 'otw_2fa_methods', $methods);
            
            // Also update old field for backward compatibility
            if (count($methods) === 1) {
                update_user_meta($user_id, 'otw_2fa_method', $method);
            }
        }
        
        return $methods;
    }
    
    /**
     * Remove a method from user's enabled methods
     */
    public static function remove_method($user_id, $method) {
        $methods = self::get_methods($user_id);
        $methods = array_filter($methods, function($m) use ($method) {
            return $m !== $method;
        });
        $methods = array_values($methods);
        
        update_user_meta($user_id, 'otw_2fa_methods', $methods);
        
        // Update old field
        if (empty($methods)) {
            delete_user_meta($user_id, 'otw_2fa_method');
        } else {
            update_user_meta($user_id, 'otw_2fa_method', $methods[0]);
        }
        
        return $methods;
    }
}
