<?php
/**
 * Admin Class
 * 
 * Handles admin settings page for 2FA configuration.
 */

namespace OTW\TwoFA;

if (!defined('ABSPATH')) {
    exit;
}

class Admin {
    
    /**
     * Constructor
     */
    public function __construct() {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this, 'register_settings']);
    }
    
    /**
     * Add admin menu
     */
    public function add_menu() {
        add_options_page(
            __('Two-Factor Authentication', 'otw-2fa'),
            __('2FA Settings', 'otw-2fa'),
            'manage_options',
            'otw-2fa-settings',
            [$this, 'render_settings_page']
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        // General Settings
        register_setting('otw_2fa_settings', 'otw_2fa_enable_totp');
        register_setting('otw_2fa_settings', 'otw_2fa_enable_email');
        register_setting('otw_2fa_settings', 'otw_2fa_enable_sms');
        register_setting('otw_2fa_settings', 'otw_2fa_required_roles');
        register_setting('otw_2fa_settings', 'otw_2fa_code_expiry');
        register_setting('otw_2fa_settings', 'otw_2fa_code_length');
        
        // SMS Provider Settings
        register_setting('otw_2fa_settings', 'otw_2fa_sms_provider');
        register_setting('otw_2fa_settings', 'otw_2fa_twilio_sid');
        register_setting('otw_2fa_settings', 'otw_2fa_twilio_token');
        register_setting('otw_2fa_settings', 'otw_2fa_twilio_phone');
        register_setting('otw_2fa_settings', 'otw_2fa_webhook_url');
        
        // General Section
        add_settings_section(
            'otw_2fa_general',
            __('General Settings', 'otw-2fa'),
            [$this, 'render_general_section'],
            'otw-2fa-settings'
        );
        
        add_settings_field(
            'otw_2fa_enable_totp',
            __('Google Authenticator', 'otw-2fa'),
            [$this, 'render_checkbox_field'],
            'otw-2fa-settings',
            'otw_2fa_general',
            [
                'id' => 'otw_2fa_enable_totp',
                'description' => __('Allow users to use Google Authenticator or other TOTP apps.', 'otw-2fa'),
            ]
        );
        
        add_settings_field(
            'otw_2fa_enable_email',
            __('Email Verification', 'otw-2fa'),
            [$this, 'render_checkbox_field'],
            'otw-2fa-settings',
            'otw_2fa_general',
            [
                'id' => 'otw_2fa_enable_email',
                'description' => __('Allow users to receive verification codes via email.', 'otw-2fa'),
            ]
        );
        
        add_settings_field(
            'otw_2fa_enable_sms',
            __('SMS Verification', 'otw-2fa'),
            [$this, 'render_checkbox_field'],
            'otw-2fa-settings',
            'otw_2fa_general',
            [
                'id' => 'otw_2fa_enable_sms',
                'description' => __('Allow users to receive verification codes via SMS.', 'otw-2fa'),
            ]
        );
        
        add_settings_field(
            'otw_2fa_code_expiry',
            __('Code Expiry (seconds)', 'otw-2fa'),
            [$this, 'render_number_field'],
            'otw-2fa-settings',
            'otw_2fa_general',
            [
                'id' => 'otw_2fa_code_expiry',
                'default' => 300,
                'min' => 60,
                'max' => 3600,
                'description' => __('How long email/SMS codes are valid.', 'otw-2fa'),
            ]
        );
        
        add_settings_field(
            'otw_2fa_code_length',
            __('Code Length', 'otw-2fa'),
            [$this, 'render_number_field'],
            'otw-2fa-settings',
            'otw_2fa_general',
            [
                'id' => 'otw_2fa_code_length',
                'default' => 6,
                'min' => 4,
                'max' => 8,
                'description' => __('Number of digits in verification codes.', 'otw-2fa'),
            ]
        );
        
        add_settings_field(
            'otw_2fa_required_roles',
            __('Required for Roles', 'otw-2fa'),
            [$this, 'render_roles_field'],
            'otw-2fa-settings',
            'otw_2fa_general',
            [
                'id' => 'otw_2fa_required_roles',
                'description' => __('2FA will be mandatory for users with these roles.', 'otw-2fa'),
            ]
        );
        
        // SMS Section
        add_settings_section(
            'otw_2fa_sms',
            __('SMS Settings', 'otw-2fa'),
            [$this, 'render_sms_section'],
            'otw-2fa-settings'
        );
        
        add_settings_field(
            'otw_2fa_sms_provider',
            __('SMS Provider', 'otw-2fa'),
            [$this, 'render_select_field'],
            'otw-2fa-settings',
            'otw_2fa_sms',
            [
                'id' => 'otw_2fa_sms_provider',
                'options' => [
                    'twilio' => 'Twilio',
                    'webhook' => __('Custom Webhook', 'otw-2fa'),
                ],
            ]
        );
        
        add_settings_field(
            'otw_2fa_twilio_sid',
            __('Twilio Account SID', 'otw-2fa'),
            [$this, 'render_text_field'],
            'otw-2fa-settings',
            'otw_2fa_sms',
            [
                'id' => 'otw_2fa_twilio_sid',
                'class' => 'twilio-field',
            ]
        );
        
        add_settings_field(
            'otw_2fa_twilio_token',
            __('Twilio Auth Token', 'otw-2fa'),
            [$this, 'render_password_field'],
            'otw-2fa-settings',
            'otw_2fa_sms',
            [
                'id' => 'otw_2fa_twilio_token',
                'class' => 'twilio-field',
            ]
        );
        
        add_settings_field(
            'otw_2fa_twilio_phone',
            __('Twilio Phone Number', 'otw-2fa'),
            [$this, 'render_text_field'],
            'otw-2fa-settings',
            'otw_2fa_sms',
            [
                'id' => 'otw_2fa_twilio_phone',
                'class' => 'twilio-field',
                'placeholder' => '+1234567890',
            ]
        );
        
        add_settings_field(
            'otw_2fa_webhook_url',
            __('Webhook URL', 'otw-2fa'),
            [$this, 'render_text_field'],
            'otw-2fa-settings',
            'otw_2fa_sms',
            [
                'id' => 'otw_2fa_webhook_url',
                'class' => 'webhook-field',
                'placeholder' => 'https://your-sms-service.com/send',
                'description' => __('POST request will be sent with: phone, message, code, site, site_url', 'otw-2fa'),
            ]
        );
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            
            <form method="post" action="options.php">
                <?php
                settings_fields('otw_2fa_settings');
                do_settings_sections('otw-2fa-settings');
                submit_button();
                ?>
            </form>
            
            <hr>
            
            <h2><?php _e('User 2FA Status', 'otw-2fa'); ?></h2>
            <?php $this->render_users_table(); ?>
        </div>
        
        <script>
        jQuery(function($) {
            function toggleProviderFields() {
                var provider = $('#otw_2fa_sms_provider').val();
                $('.twilio-field').closest('tr').toggle(provider === 'twilio');
                $('.webhook-field').closest('tr').toggle(provider === 'webhook');
            }
            
            $('#otw_2fa_sms_provider').on('change', toggleProviderFields);
            toggleProviderFields();
        });
        </script>
        <?php
    }
    
    /**
     * Render general section description
     */
    public function render_general_section() {
        echo '<p>' . __('Configure which 2FA methods are available for users.', 'otw-2fa') . '</p>';
    }
    
    /**
     * Render SMS section description
     */
    public function render_sms_section() {
        echo '<p>' . __('Configure SMS provider settings for SMS-based verification.', 'otw-2fa') . '</p>';
    }
    
    /**
     * Render checkbox field
     */
    public function render_checkbox_field($args) {
        $value = get_option($args['id'], 1);
        ?>
        <label>
            <input type="checkbox" id="<?php echo esc_attr($args['id']); ?>" 
                   name="<?php echo esc_attr($args['id']); ?>" 
                   value="1" <?php checked(1, $value); ?>>
            <?php if (!empty($args['description'])): ?>
                <?php echo esc_html($args['description']); ?>
            <?php endif; ?>
        </label>
        <?php
    }
    
    /**
     * Render number field
     */
    public function render_number_field($args) {
        $value = get_option($args['id'], $args['default'] ?? 0);
        ?>
        <input type="number" id="<?php echo esc_attr($args['id']); ?>" 
               name="<?php echo esc_attr($args['id']); ?>" 
               value="<?php echo esc_attr($value); ?>"
               min="<?php echo esc_attr($args['min'] ?? 0); ?>"
               max="<?php echo esc_attr($args['max'] ?? 99999); ?>"
               class="small-text">
        <?php if (!empty($args['description'])): ?>
            <p class="description"><?php echo esc_html($args['description']); ?></p>
        <?php endif;
    }
    
    /**
     * Render text field
     */
    public function render_text_field($args) {
        $value = get_option($args['id'], '');
        ?>
        <input type="text" id="<?php echo esc_attr($args['id']); ?>" 
               name="<?php echo esc_attr($args['id']); ?>" 
               value="<?php echo esc_attr($value); ?>"
               class="regular-text <?php echo esc_attr($args['class'] ?? ''); ?>"
               placeholder="<?php echo esc_attr($args['placeholder'] ?? ''); ?>">
        <?php if (!empty($args['description'])): ?>
            <p class="description"><?php echo esc_html($args['description']); ?></p>
        <?php endif;
    }
    
    /**
     * Render password field
     */
    public function render_password_field($args) {
        $value = get_option($args['id'], '');
        ?>
        <input type="password" id="<?php echo esc_attr($args['id']); ?>" 
               name="<?php echo esc_attr($args['id']); ?>" 
               value="<?php echo esc_attr($value); ?>"
               class="regular-text <?php echo esc_attr($args['class'] ?? ''); ?>">
        <?php
    }
    
    /**
     * Render select field
     */
    public function render_select_field($args) {
        $value = get_option($args['id'], '');
        ?>
        <select id="<?php echo esc_attr($args['id']); ?>" 
                name="<?php echo esc_attr($args['id']); ?>">
            <?php foreach ($args['options'] as $key => $label): ?>
                <option value="<?php echo esc_attr($key); ?>" <?php selected($value, $key); ?>>
                    <?php echo esc_html($label); ?>
                </option>
            <?php endforeach; ?>
        </select>
        <?php
    }
    
    /**
     * Render roles field
     */
    public function render_roles_field($args) {
        $selected_roles = get_option($args['id'], []);
        if (!is_array($selected_roles)) {
            $selected_roles = [];
        }
        
        $roles = wp_roles()->roles;
        
        foreach ($roles as $role_key => $role) {
            ?>
            <label style="display: block; margin-bottom: 5px;">
                <input type="checkbox" 
                       name="<?php echo esc_attr($args['id']); ?>[]" 
                       value="<?php echo esc_attr($role_key); ?>"
                       <?php checked(in_array($role_key, $selected_roles)); ?>>
                <?php echo esc_html($role['name']); ?>
            </label>
            <?php
        }
        
        if (!empty($args['description'])) {
            echo '<p class="description">' . esc_html($args['description']) . '</p>';
        }
    }
    
    /**
     * Render users 2FA status table
     */
    private function render_users_table() {
        $users = get_users([
            'number' => 50,
            'orderby' => 'registered',
            'order' => 'DESC',
        ]);
        
        ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php _e('User', 'otw-2fa'); ?></th>
                    <th><?php _e('Role', 'otw-2fa'); ?></th>
                    <th><?php _e('2FA Status', 'otw-2fa'); ?></th>
                    <th><?php _e('Method', 'otw-2fa'); ?></th>
                    <th><?php _e('Backup Codes', 'otw-2fa'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($users as $user): 
                    $method = User_Settings::get_method($user->ID);
                    $is_enabled = User_Settings::is_enabled($user->ID);
                    $backup_codes = get_user_meta($user->ID, 'otw_2fa_backup_codes', true);
                    $backup_count = is_array($backup_codes) ? count($backup_codes) : 0;
                ?>
                <tr>
                    <td>
                        <a href="<?php echo esc_url(get_edit_user_link($user->ID)); ?>">
                            <?php echo esc_html($user->display_name); ?>
                        </a>
                        <br>
                        <small><?php echo esc_html($user->user_email); ?></small>
                    </td>
                    <td><?php echo esc_html(implode(', ', $user->roles)); ?></td>
                    <td>
                        <?php if ($is_enabled): ?>
                            <span style="color: green;">✓ <?php _e('Enabled', 'otw-2fa'); ?></span>
                        <?php else: ?>
                            <span style="color: #999;">✗ <?php _e('Disabled', 'otw-2fa'); ?></span>
                        <?php endif; ?>
                    </td>
                    <td><?php echo $is_enabled ? esc_html(ucfirst($method)) : '—'; ?></td>
                    <td><?php echo $is_enabled ? $backup_count : '—'; ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }
}
