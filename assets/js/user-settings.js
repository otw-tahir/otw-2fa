/**
 * OTW 2FA - User Settings JavaScript
 */

(function($) {
    'use strict';

    // State
    var currentMethod = 'totp';

    /**
     * Initialize
     */
    function init() {
        bindEvents();
        toggleSetupSections();
    }

    /**
     * Bind events
     */
    function bindEvents() {
        // Method selection
        $('input[name="otw_2fa_setup_method"]').on('change', function() {
            currentMethod = $(this).val();
            toggleSetupSections();
        });

        // TOTP: Generate secret
        $('#otw-2fa-generate-secret').on('click', generateSecret);

        // TOTP: Verify
        $('#otw-2fa-verify-totp').on('click', function() {
            verifyCode('totp', $('#otw-2fa-verify-code').val());
        });

        // Email: Send test
        $('#otw-2fa-send-test-email').on('click', sendTestEmail);

        // Email: Verify
        $('#otw-2fa-verify-email').on('click', function() {
            verifyCode('email', $('#otw-2fa-email-code').val());
        });

        // SMS: Send test
        $('#otw-2fa-send-test-sms').on('click', sendTestSMS);

        // SMS: Verify
        $('#otw-2fa-verify-sms').on('click', function() {
            verifyCode('sms', $('#otw-2fa-sms-code').val());
        });

        // Disable 2FA
        $('.otw-2fa-disable-btn').on('click', disable2FA);

        // Generate backup codes
        $('#otw-2fa-generate-backup-codes').on('click', generateBackupCodes);

        // Enter key handling
        $('#otw-2fa-verify-code, #otw-2fa-email-code, #otw-2fa-sms-code').on('keypress', function(e) {
            if (e.which === 13) {
                e.preventDefault();
                $(this).siblings('button').click();
            }
        });
    }

    /**
     * Toggle setup sections based on selected method
     */
    function toggleSetupSections() {
        $('.otw-2fa-setup-section').hide();
        $('.otw-2fa-setup-' + currentMethod).show();
    }

    /**
     * Generate TOTP secret
     */
    function generateSecret() {
        var $btn = $('#otw-2fa-generate-secret');
        $btn.text(otw2fa.strings.generating).prop('disabled', true);

        $.ajax({
            url: otw2fa.ajaxUrl,
            type: 'POST',
            data: {
                action: 'otw_2fa_generate_secret',
                nonce: otw2fa.nonce
            },
            success: function(response) {
                if (response.success) {
                    $('#otw-2fa-qr-code').attr('src', response.data.qr_url);
                    $('#otw-2fa-secret-display').text(response.data.secret);
                    $('#otw-2fa-secret').val(response.data.secret);
                    $('.otw-2fa-qr-container').show();
                    $('#otw-2fa-verify-code').focus();
                } else {
                    showMessage($btn, response.data.message, 'error');
                }
            },
            error: function() {
                showMessage($btn, otw2fa.strings.error, 'error');
            },
            complete: function() {
                $btn.text($btn.data('original-text') || 'Generate New Secret').prop('disabled', false);
            }
        });
    }

    /**
     * Send test email
     */
    function sendTestEmail() {
        var $btn = $('#otw-2fa-send-test-email');
        $btn.text(otw2fa.strings.sending).prop('disabled', true);

        $.ajax({
            url: otw2fa.ajaxUrl,
            type: 'POST',
            data: {
                action: 'otw_2fa_send_test_email',
                nonce: otw2fa.nonce
            },
            success: function(response) {
                if (response.success) {
                    $('.otw-2fa-email-verify').show();
                    $('#otw-2fa-email-code').focus();
                    showMessage($btn, otw2fa.strings.codeSent, 'success');
                } else {
                    showMessage($btn, response.data.message, 'error');
                }
            },
            error: function() {
                showMessage($btn, otw2fa.strings.error, 'error');
            },
            complete: function() {
                $btn.text('Send Test Code').prop('disabled', false);
            }
        });
    }

    /**
     * Send test SMS
     */
    function sendTestSMS() {
        var $btn = $('#otw-2fa-send-test-sms');
        var phone = $('#otw-2fa-phone').val();

        if (!phone) {
            showMessage($btn, 'Please enter a phone number', 'error');
            return;
        }

        $btn.text(otw2fa.strings.sending).prop('disabled', true);

        $.ajax({
            url: otw2fa.ajaxUrl,
            type: 'POST',
            data: {
                action: 'otw_2fa_send_test_sms',
                nonce: otw2fa.nonce,
                phone: phone
            },
            success: function(response) {
                if (response.success) {
                    $('.otw-2fa-sms-verify').show();
                    $('#otw-2fa-sms-code').focus();
                    showMessage($btn, otw2fa.strings.smsSent, 'success');
                } else {
                    showMessage($btn, response.data.message, 'error');
                }
            },
            error: function() {
                showMessage($btn, otw2fa.strings.error, 'error');
            },
            complete: function() {
                $btn.text('Send Test Code').prop('disabled', false);
            }
        });
    }

    /**
     * Verify code and enable 2FA
     */
    function verifyCode(method, code) {
        var $btn = $('#otw-2fa-verify-' + method);
        var $input = $btn.siblings('input');

        if (!code || code.length < 4) {
            showMessage($btn, otw2fa.strings.invalidCode, 'error');
            $input.focus();
            return;
        }

        $btn.text(otw2fa.strings.verifying).prop('disabled', true);

        $.ajax({
            url: otw2fa.ajaxUrl,
            type: 'POST',
            data: {
                action: 'otw_2fa_verify_setup',
                nonce: otw2fa.nonce,
                method: method,
                code: code
            },
            success: function(response) {
                if (response.success) {
                    showMessage($btn, otw2fa.strings.verified, 'success');
                    
                    // Show backup codes if provided
                    if (response.data.backup_codes) {
                        showBackupCodes(response.data.backup_codes);
                    }
                    
                    // Reload page after delay
                    setTimeout(function() {
                        location.reload();
                    }, 3000);
                } else {
                    showMessage($btn, response.data.message, 'error');
                    $input.val('').focus();
                }
            },
            error: function() {
                showMessage($btn, otw2fa.strings.error, 'error');
            },
            complete: function() {
                $btn.text('Verify & Enable').prop('disabled', false);
            }
        });
    }

    /**
     * Disable 2FA
     */
    function disable2FA() {
        if (!confirm(otw2fa.strings.confirmDisable)) {
            return;
        }

        var $btn = $(this);
        var userId = $btn.data('user-id');

        $btn.prop('disabled', true);

        $.ajax({
            url: otw2fa.ajaxUrl,
            type: 'POST',
            data: {
                action: 'otw_2fa_disable',
                nonce: otw2fa.nonce,
                user_id: userId
            },
            success: function(response) {
                if (response.success) {
                    location.reload();
                } else {
                    alert(response.data.message);
                    $btn.prop('disabled', false);
                }
            },
            error: function() {
                alert(otw2fa.strings.error);
                $btn.prop('disabled', false);
            }
        });
    }

    /**
     * Generate new backup codes
     */
    function generateBackupCodes() {
        var $btn = $('#otw-2fa-generate-backup-codes');
        
        if (!confirm('This will invalidate all existing backup codes. Continue?')) {
            return;
        }

        $btn.text('Generating...').prop('disabled', true);

        $.ajax({
            url: otw2fa.ajaxUrl,
            type: 'POST',
            data: {
                action: 'otw_2fa_generate_backup_codes',
                nonce: otw2fa.nonce
            },
            success: function(response) {
                if (response.success) {
                    showBackupCodes(response.data.backup_codes);
                } else {
                    alert(response.data.message);
                }
            },
            error: function() {
                alert(otw2fa.strings.error);
            },
            complete: function() {
                $btn.text('Generate New Backup Codes').prop('disabled', false);
            }
        });
    }

    /**
     * Show backup codes
     */
    function showBackupCodes(codes) {
        var $container = $('#otw-2fa-backup-codes-display');
        
        var html = '<h4>Your Backup Codes</h4>';
        html += '<div class="backup-codes-list">';
        codes.forEach(function(code) {
            html += '<code>' + code + '</code>';
        });
        html += '</div>';
        html += '<div class="backup-codes-warning">';
        html += '<strong>Important:</strong> Save these codes in a safe place. Each code can only be used once. They will not be shown again.';
        html += '</div>';
        
        $container.html(html).show();
    }

    /**
     * Show message near element
     */
    function showMessage($element, message, type) {
        var $msg = $element.siblings('.otw-2fa-message');
        
        if (!$msg.length) {
            $msg = $('<span class="otw-2fa-message"></span>');
            $element.after($msg);
        }
        
        $msg.removeClass('success error').addClass(type).text(message).show();
        
        setTimeout(function() {
            $msg.fadeOut();
        }, 5000);
    }

    // Initialize on DOM ready
    $(document).ready(init);

})(jQuery);
