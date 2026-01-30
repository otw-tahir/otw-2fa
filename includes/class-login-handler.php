<?php
/**
 * Login Handler Class
 * 
 * Handles 2FA verification during WordPress login.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class Login_Handler {
    
    /**
     * Constructor
     */
    public function __construct() {
        // Intercept login
        add_filter('authenticate', [$this, 'check_2fa'], 999, 3);
        
        // Handle 2FA verification form
        add_action('login_form_otw_2fa_verify', [$this, 'handle_2fa_verification']);
        
        // Add custom login form for 2FA
        add_action('login_enqueue_scripts', [$this, 'enqueue_login_scripts']);
        
        // AJAX for resending codes
        add_action('wp_ajax_nopriv_otw_2fa_resend_code', [$this, 'ajax_resend_code']);
    }
    
    /**
     * Enqueue login page scripts
     */
    public function enqueue_login_scripts() {
        wp_enqueue_style(
            'otw-2fa-login',
            OTW_2FA_PLUGIN_URL . 'assets/css/login.css',
            [],
            OTW_2FA_VERSION
        );
    }
    
    /**
     * Check if 2FA is required after password verification
     */
    public function check_2fa($user, $username, $password) {
        // If not a valid user object, let WordPress handle it
        if (!$user instanceof \WP_User) {
            return $user;
        }
        
        // Check if 2FA is enabled for this user
        if (!User_Settings::is_enabled($user->ID)) {
            return $user;
        }
        
        // Check if this is already a 2FA verification request
        if (isset($_POST['otw_2fa_token']) && isset($_POST['otw_2fa_code'])) {
            return $user; // Will be handled by verification
        }
        
        // Store login info temporarily and redirect to 2FA
        $token = wp_generate_password(32, false);
        
        set_transient('otw_2fa_pending_login_' . $token, [
            'user_id' => $user->ID,
            'remember' => !empty($_POST['rememberme']),
            'redirect_to' => isset($_POST['redirect_to']) ? $_POST['redirect_to'] : admin_url(),
            'created' => time(),
        ], 300); // 5 minutes
        
        // Get user's 2FA method
        $method = User_Settings::get_method($user->ID);
        
        // For email/SMS, send the code now
        if ($method === 'email') {
            Email_OTP::send_code($user->ID);
        } elseif ($method === 'sms') {
            SMS_OTP::send_code($user->ID);
        }
        
        // Redirect to 2FA verification page
        $verify_url = add_query_arg([
            'action' => 'otw_2fa_verify',
            'token' => $token,
        ], wp_login_url());
        
        wp_safe_redirect($verify_url);
        exit;
    }
    
    /**
     * Handle 2FA verification form display and submission
     */
    public function handle_2fa_verification() {
        $token = sanitize_text_field($_GET['token'] ?? $_POST['otw_2fa_token'] ?? '');
        
        if (empty($token)) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        $pending = get_transient('otw_2fa_pending_login_' . $token);
        
        if (!$pending) {
            // Token expired
            $this->show_error(__('Your session has expired. Please log in again.', 'otw-2fa'));
            return;
        }
        
        $user = get_userdata($pending['user_id']);
        
        if (!$user) {
            wp_safe_redirect(wp_login_url());
            exit;
        }
        
        $method = User_Settings::get_method($user->ID);
        $error = '';
        
        // Handle form submission
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['otw_2fa_code'])) {
            $code = sanitize_text_field($_POST['otw_2fa_code']);
            $verified = false;
            
            // Try verification code first
            switch ($method) {
                case 'totp':
                    $secret = get_user_meta($user->ID, 'otw_2fa_totp_secret', true);
                    $verified = TOTP::verify_code($secret, $code);
                    break;
                    
                case 'email':
                    $verified = Email_OTP::verify_code($user->ID, $code);
                    break;
                    
                case 'sms':
                    $verified = SMS_OTP::verify_code($user->ID, $code);
                    break;
            }
            
            // If not verified, try backup code
            if (!$verified) {
                $verified = $this->verify_backup_code($user->ID, $code);
            }
            
            if ($verified) {
                // Delete the pending login
                delete_transient('otw_2fa_pending_login_' . $token);
                
                // Log the user in
                wp_set_auth_cookie($user->ID, $pending['remember']);
                
                // Redirect
                $redirect_to = !empty($pending['redirect_to']) ? $pending['redirect_to'] : admin_url();
                wp_safe_redirect($redirect_to);
                exit;
            } else {
                $error = __('Invalid verification code. Please try again.', 'otw-2fa');
            }
        }
        
        // Show 2FA verification form
        $this->render_verification_form($user, $method, $token, $error);
        exit;
    }
    
    /**
     * Render 2FA verification form
     */
    private function render_verification_form($user, $method, $token, $error = '') {
        $method_labels = [
            'totp' => __('Enter the code from your authenticator app', 'otw-2fa'),
            'email' => sprintf(__('Enter the code sent to %s', 'otw-2fa'), Email_OTP::mask_email($user->user_email)),
            'sms' => sprintf(__('Enter the code sent to %s', 'otw-2fa'), SMS_OTP::mask_phone(get_user_meta($user->ID, 'otw_2fa_phone', true))),
        ];
        
        login_header(__('Two-Factor Authentication', 'otw-2fa'));
        ?>
        
        <form name="otw_2fa_form" id="otw_2fa_form" action="" method="post">
            <input type="hidden" name="otw_2fa_token" value="<?php echo esc_attr($token); ?>">
            
            <?php if ($error): ?>
                <div id="login_error"><?php echo esc_html($error); ?></div>
            <?php endif; ?>
            
            <p class="otw-2fa-prompt">
                <?php echo esc_html($method_labels[$method] ?? __('Enter your verification code', 'otw-2fa')); ?>
            </p>
            
            <p>
                <label for="otw_2fa_code"><?php _e('Verification Code', 'otw-2fa'); ?></label>
                <input type="text" name="otw_2fa_code" id="otw_2fa_code" class="input" 
                       size="20" autocomplete="off" autofocus 
                       pattern="[0-9A-Za-z]*" maxlength="10"
                       placeholder="<?php echo $method === 'totp' ? '123456' : '123456'; ?>">
            </p>
            
            <p class="submit">
                <input type="submit" name="wp-submit" id="wp-submit" 
                       class="button button-primary button-large" 
                       value="<?php esc_attr_e('Verify', 'otw-2fa'); ?>">
            </p>
            
            <?php if (in_array($method, ['email', 'sms'])): ?>
            <p class="otw-2fa-resend">
                <a href="#" id="otw-2fa-resend-link" data-token="<?php echo esc_attr($token); ?>" data-method="<?php echo esc_attr($method); ?>">
                    <?php _e("Didn't receive a code? Resend", 'otw-2fa'); ?>
                </a>
                <span id="otw-2fa-resend-message" style="display: none;"></span>
            </p>
            <?php endif; ?>
            
            <p class="otw-2fa-backup">
                <a href="#" id="otw-2fa-use-backup">
                    <?php _e('Use a backup code', 'otw-2fa'); ?>
                </a>
            </p>
        </form>
        
        <p id="backtoblog">
            <a href="<?php echo esc_url(home_url('/')); ?>">
                &larr; <?php printf(__('Go to %s', 'otw-2fa'), get_bloginfo('title')); ?>
            </a>
        </p>
        
        <script>
        document.getElementById('otw-2fa-resend-link')?.addEventListener('click', function(e) {
            e.preventDefault();
            var link = this;
            var message = document.getElementById('otw-2fa-resend-message');
            
            link.style.display = 'none';
            message.style.display = 'inline';
            message.textContent = '<?php _e('Sending...', 'otw-2fa'); ?>';
            
            fetch('<?php echo admin_url('admin-ajax.php'); ?>', {
                method: 'POST',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body: 'action=otw_2fa_resend_code&token=' + encodeURIComponent(link.dataset.token)
            })
            .then(response => response.json())
            .then(data => {
                message.textContent = data.success ? '<?php _e('Code sent!', 'otw-2fa'); ?>' : data.data.message;
                setTimeout(() => {
                    link.style.display = 'inline';
                    message.style.display = 'none';
                }, 3000);
            })
            .catch(() => {
                message.textContent = '<?php _e('Failed to send code.', 'otw-2fa'); ?>';
                setTimeout(() => {
                    link.style.display = 'inline';
                    message.style.display = 'none';
                }, 3000);
            });
        });
        </script>
        
        <?php
        login_footer();
    }
    
    /**
     * Show error on login page
     */
    private function show_error($message) {
        login_header(__('Error', 'otw-2fa'));
        ?>
        <div id="login_error"><?php echo esc_html($message); ?></div>
        <p id="backtoblog">
            <a href="<?php echo esc_url(wp_login_url()); ?>">
                &larr; <?php _e('Back to login', 'otw-2fa'); ?>
            </a>
        </p>
        <?php
        login_footer();
        exit;
    }
    
    /**
     * Verify backup code
     */
    private function verify_backup_code($user_id, $code) {
        $code = strtoupper(preg_replace('/[^A-Za-z0-9]/', '', $code));
        $backup_codes = get_user_meta($user_id, 'otw_2fa_backup_codes', true);
        
        if (!is_array($backup_codes) || empty($backup_codes)) {
            return false;
        }
        
        foreach ($backup_codes as $index => $hashed_code) {
            if (wp_check_password($code, $hashed_code)) {
                // Remove used backup code
                unset($backup_codes[$index]);
                update_user_meta($user_id, 'otw_2fa_backup_codes', array_values($backup_codes));
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * AJAX: Resend verification code
     */
    public function ajax_resend_code() {
        $token = sanitize_text_field($_POST['token'] ?? '');
        
        if (empty($token)) {
            wp_send_json_error(['message' => __('Invalid request.', 'otw-2fa')]);
        }
        
        $pending = get_transient('otw_2fa_pending_login_' . $token);
        
        if (!$pending) {
            wp_send_json_error(['message' => __('Session expired.', 'otw-2fa')]);
        }
        
        $user_id = $pending['user_id'];
        $method = User_Settings::get_method($user_id);
        
        $sent = false;
        
        if ($method === 'email') {
            $sent = Email_OTP::send_code($user_id);
        } elseif ($method === 'sms') {
            $result = SMS_OTP::send_code($user_id);
            $sent = $result === true;
            
            if (is_wp_error($result)) {
                wp_send_json_error(['message' => $result->get_error_message()]);
            }
        }
        
        if ($sent) {
            wp_send_json_success(['message' => __('Code sent!', 'otw-2fa')]);
        } else {
            wp_send_json_error(['message' => __('Failed to send code.', 'otw-2fa')]);
        }
    }
}
