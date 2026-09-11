<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Settings screen: Settings -> Entra ID SSO.
 *
 * Everything here is per-site config. The shared secret entered here must
 * match exactly what's in the proxy's sites.json for this site's site_id -
 * that's what lets the proxy and this site trust each other's handoff token.
 */
final class TTM_Entra_SSO_Settings
{
    public const OPTION_KEY = 'ttm_entra_sso_settings';
    public const ENROLL_KEY_CONSTANT = 'TTM_ENTRA_SSO_ENROLL_KEY';
    private const NONCE_ACTION = 'ttm_entra_sso_reconnect';
    private const ENROLL_LOCK_TRANSIENT = 'ttm_entra_sso_enroll_lock';
    private const JUST_ENROLLED_TRANSIENT = 'ttm_entra_sso_just_enrolled';

    /**
     * Must match TTM_Entra_SSO_Proxy_Config::DEFAULT_ENROLL_KEY on the proxy.
     * Shared across every TTM-managed install by design, but never sent over
     * the wire: it's only used locally to answer the proxy's domain-control
     * challenge (see handle_enroll_challenge()) with an HMAC the proxy can
     * verify - see TTM_Entra_SSO_Proxy_Rest_Routes::verify_domain_control()
     * for why that's safe even though this value ships in public source.
     * Override via the same-named wp-config.php constant if it's ever
     * rotated.
     */
    private const DEFAULT_ENROLL_KEY = '292a2a0521e894918f79cd896244e4d4286f8b8ce432ec48ffcdf219266ac0ea';

    public static function init(): void
    {
        add_action('admin_menu', [self::class, 'register_menu']);
        add_action('admin_init', [self::class, 'register_settings']);
        add_action('admin_init', [self::class, 'maybe_enroll']);
        add_action('admin_notices', [self::class, 'render_enroll_notice']);
        add_action('admin_post_' . self::NONCE_ACTION, [self::class, 'handle_reconnect']);
        add_action('rest_api_init', [self::class, 'register_challenge_route']);
    }

    /**
     * Answers the proxy's enroll() domain-control challenge: proves this
     * site is genuinely reachable at its own URL and running a copy of this
     * plugin, without ever transmitting the shared key itself.
     */
    public static function register_challenge_route(): void
    {
        // Namespace must match TTM_Entra_SSO::REST_NAMESPACE.
        register_rest_route('ttm-entra-sso/v1', '/enroll-challenge', [
            'methods' => 'GET',
            'callback' => [self::class, 'handle_enroll_challenge'],
            'permission_callback' => '__return_true',
            'args' => [
                'nonce' => [
                    'required' => true,
                    'type' => 'string',
                ],
            ],
        ]);
    }

    public static function handle_enroll_challenge(WP_REST_Request $request): WP_REST_Response
    {
        $nonce = (string) $request->get_param('nonce');
        if ($nonce === '' || !ctype_xdigit($nonce)) {
            return new WP_REST_Response(['error' => 'Missing or invalid nonce.'], 400);
        }

        return new WP_REST_Response(['response' => hash_hmac('sha256', $nonce, self::enroll_key())], 200);
    }

    /**
     * @return array<string, mixed>
     */
    public static function get(): array
    {
        $defaults = [
            'proxy_url' => 'https://mainwp.talktomedia.co.uk',
            'site_id' => '',
            'shared_secret' => '',
            'allowed_email_domain' => 'talktomedia.co.uk',
            'auto_create_users' => '1',
            'default_role' => 'editor',
            'redirect_after_login' => admin_url(),
            'allowed_ips' => '138.124.134.52',
            'ip_header' => 'remote_addr',
            'verify_remote_status' => '1',
        ];

        return wp_parse_args(get_option(self::OPTION_KEY, []), $defaults);
    }

    public static function register_menu(): void
    {
        add_options_page(
            'Entra ID SSO',
            'Entra ID SSO',
            'manage_options',
            'ttm-entra-sso',
            [self::class, 'render_page']
        );
    }

    public static function register_settings(): void
    {
        register_setting(self::OPTION_KEY, self::OPTION_KEY, [self::class, 'sanitize']);
    }

    /**
     * Self-provisioning: if this site doesn't have a site_id/shared_secret
     * yet, ask the proxy for one instead of requiring someone to visit this
     * settings screen and paste values in by hand. Runs on every wp-admin
     * load until it succeeds (rate-limited via a transient lock so a proxy
     * that's temporarily unreachable, or the MainWP extension not being
     * enabled yet, doesn't get hit on every request) - so rolling this
     * plugin out across many sites is just "install and activate", it wires
     * itself up the first time an admin visits any wp-admin page.
     */
    public static function maybe_enroll(): void
    {
        $settings = self::get();

        if ($settings['site_id'] !== '' && $settings['shared_secret'] !== '') {
            return; // Already configured - possibly by hand, don't overwrite it.
        }

        if (empty($settings['proxy_url']) || get_transient(self::ENROLL_LOCK_TRANSIENT)) {
            return;
        }

        set_transient(self::ENROLL_LOCK_TRANSIENT, 1, 5 * MINUTE_IN_SECONDS);

        self::attempt_enroll($settings['proxy_url']);
    }

    private static function attempt_enroll(string $proxyUrl): void
    {
        $response = wp_remote_post(
            untrailingslashit($proxyUrl) . '/wp-json/ttm-entra-sso-proxy/v1/enroll',
            [
                'timeout' => 8,
                'body' => [
                    'site_url' => home_url(),
                ],
            ]
        );

        if (is_wp_error($response)) {
            error_log('[ttm-entra-sso] auto-enroll request failed: ' . $response->get_error_message());
            return;
        }

        $status = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (!in_array($status, [200, 201], true) || !is_array($body) || empty($body['site_id']) || empty($body['shared_secret'])) {
            $detail = is_array($body) ? ($body['error'] ?? 'unknown error') : 'unparsable response';
            error_log("[ttm-entra-sso] auto-enroll not completed ({$status}): {$detail}");
            return;
        }

        $current = self::get();
        $current['site_id'] = sanitize_text_field((string) $body['site_id']);
        $current['shared_secret'] = trim((string) $body['shared_secret']);
        update_option(self::OPTION_KEY, $current, false);

        delete_transient(self::ENROLL_LOCK_TRANSIENT);
        set_transient(self::JUST_ENROLLED_TRANSIENT, $current['site_id'], MINUTE_IN_SECONDS);
    }

    /**
     * Manual escape hatch for troubleshooting: bypasses the rate-limit lock
     * and re-runs enrollment immediately, e.g. right after the MainWP
     * extension gets enabled, or to pick up new credentials after the proxy
     * regenerated this site's secret.
     */
    public static function handle_reconnect(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('Insufficient permissions.');
        }
        check_admin_referer(self::NONCE_ACTION);

        delete_transient(self::ENROLL_LOCK_TRANSIENT);

        $settings = self::get();
        if (!empty($settings['proxy_url'])) {
            self::attempt_enroll($settings['proxy_url']);
        }

        wp_safe_redirect(admin_url('options-general.php?page=ttm-entra-sso'));
        exit;
    }

    public static function render_enroll_notice(): void
    {
        $siteId = get_transient(self::JUST_ENROLLED_TRANSIENT);
        if (!$siteId || !current_user_can('manage_options')) {
            return;
        }

        delete_transient(self::JUST_ENROLLED_TRANSIENT);

        printf(
            '<div class="notice notice-success is-dismissible"><p>%s</p></div>',
            esc_html(sprintf('Entra ID SSO connected automatically to the TTM proxy (site ID: %s).', $siteId))
        );
    }

    private static function enroll_key(): string
    {
        if (defined(self::ENROLL_KEY_CONSTANT)) {
            return (string) constant(self::ENROLL_KEY_CONSTANT);
        }

        return self::DEFAULT_ENROLL_KEY;
    }

    /**
     * @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    public static function sanitize(array $input): array
    {
        return [
            'proxy_url' => untrailingslashit(esc_url_raw($input['proxy_url'] ?? '')),
            'site_id' => sanitize_text_field($input['site_id'] ?? ''),
            'shared_secret' => trim((string) ($input['shared_secret'] ?? '')),
            'allowed_email_domain' => sanitize_text_field($input['allowed_email_domain'] ?? ''),
            'auto_create_users' => !empty($input['auto_create_users']) ? '1' : '0',
            'default_role' => sanitize_text_field($input['default_role'] ?? 'subscriber'),
            'redirect_after_login' => esc_url_raw($input['redirect_after_login'] ?? admin_url()),
            'allowed_ips' => sanitize_textarea_field($input['allowed_ips'] ?? ''),
            'ip_header' => in_array($input['ip_header'] ?? '', ['remote_addr', 'cf_connecting_ip', 'x_forwarded_for'], true)
                ? $input['ip_header']
                : 'remote_addr',
            'verify_remote_status' => !empty($input['verify_remote_status']) ? '1' : '0',
        ];
    }

    public static function render_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        $settings = self::get();
        $callback_url = rest_url('ttm-entra-sso/v1/callback');
        ?>
        <div class="wrap">
            <h1>Entra ID SSO</h1>
            <?php if ($settings['site_id'] === '' || $settings['shared_secret'] === '') : ?>
                <p>
                    Not connected yet. This site tries to auto-connect to the TTM SSO proxy on its own
                    (no need to fill in Site ID / Shared secret by hand) - this can take a minute after
                    first activating the plugin, or until this site shows up in MainWP's own site list.
                </p>
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="margin-bottom:1.5em;">
                    <?php wp_nonce_field(self::NONCE_ACTION); ?>
                    <input type="hidden" name="action" value="<?php echo esc_attr(self::NONCE_ACTION); ?>">
                    <?php submit_button('Try connecting now', 'secondary', 'submit', false); ?>
                </form>
            <?php else : ?>
                <p>
                    Connected (site ID: <code><?php echo esc_html($settings['site_id']); ?></code>).
                    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline;">
                        <?php wp_nonce_field(self::NONCE_ACTION); ?>
                        <input type="hidden" name="action" value="<?php echo esc_attr(self::NONCE_ACTION); ?>">
                        <?php submit_button('Reconnect', 'secondary small', 'submit', false); ?>
                    </form>
                    <span class="description">Only needed if the proxy regenerated this site's secret, or after a domain change.</span>
                </p>
            <?php endif; ?>
            <p>
                Give this to whoever manages the TTM SSO proxy so they can register this site manually if auto-connect isn't available:
                <br>
                <strong>Return URL:</strong> <code><?php echo esc_html($callback_url); ?></code>
            </p>
            <form method="post" action="options.php">
                <?php settings_fields(self::OPTION_KEY); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="ttm_proxy_url">Proxy URL</label></th>
                        <td>
                            <input type="url" id="ttm_proxy_url" class="regular-text"
                                name="<?php echo esc_attr(self::OPTION_KEY); ?>[proxy_url]"
                                value="<?php echo esc_attr($settings['proxy_url']); ?>"
                                placeholder="https://dashboard.talktomedia.co.uk">
                            <p class="description">Base URL of the site running the TTM Entra ID SSO Proxy plugin (your MainWP Dashboard install). No path needed - just the site's URL.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_site_id">Site ID</label></th>
                        <td>
                            <input type="text" id="ttm_site_id" class="regular-text"
                                name="<?php echo esc_attr(self::OPTION_KEY); ?>[site_id]"
                                value="<?php echo esc_attr($settings['site_id']); ?>">
                            <p class="description">Must match the key used for this site in the proxy's site registry.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_shared_secret">Shared secret</label></th>
                        <td>
                            <input type="password" id="ttm_shared_secret" class="regular-text" autocomplete="off"
                                name="<?php echo esc_attr(self::OPTION_KEY); ?>[shared_secret]"
                                value="<?php echo esc_attr($settings['shared_secret']); ?>">
                            <p class="description">Must match this site's <code>shared_secret</code> in the proxy's registry exactly.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_allowed_domain">Allowed email domain</label></th>
                        <td>
                            <input type="text" id="ttm_allowed_domain" class="regular-text"
                                name="<?php echo esc_attr(self::OPTION_KEY); ?>[allowed_email_domain]"
                                value="<?php echo esc_attr($settings['allowed_email_domain']); ?>"
                                placeholder="talktomedia.co.uk">
                            <p class="description">Optional, defence in depth. Leave blank to accept any domain the proxy allows.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Auto-create users</th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr(self::OPTION_KEY); ?>[auto_create_users]"
                                    value="1" <?php checked($settings['auto_create_users'], '1'); ?>>
                                Create a new WordPress user if no existing user matches the Entra email
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_default_role">Default role</label></th>
                        <td>
                            <select id="ttm_default_role" name="<?php echo esc_attr(self::OPTION_KEY); ?>[default_role]">
                                <?php foreach (wp_roles()->get_names() as $role_key => $role_name) : ?>
                                    <option value="<?php echo esc_attr($role_key); ?>" <?php selected($settings['default_role'], $role_key); ?>>
                                        <?php echo esc_html($role_name); ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <p class="description">Role assigned to auto-created users only.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_redirect">Redirect after login</label></th>
                        <td>
                            <input type="url" id="ttm_redirect" class="regular-text"
                                name="<?php echo esc_attr(self::OPTION_KEY); ?>[redirect_after_login]"
                                value="<?php echo esc_attr($settings['redirect_after_login']); ?>">
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_allowed_ips">Restrict to IP(s)</label></th>
                        <td>
                            <textarea id="ttm_allowed_ips" class="regular-text" rows="3"
                                name="<?php echo esc_attr(self::OPTION_KEY); ?>[allowed_ips]"
                                placeholder="203.0.113.10&#10;198.51.100.0/24"><?php echo esc_textarea($settings['allowed_ips']); ?></textarea>
                            <p class="description">
                                One IP or IPv4 CIDR range per line (or comma separated). Leave blank to allow any IP.
                                When set, the "Sign in with Microsoft" button is hidden outside these IPs <strong>and</strong>
                                sign-in itself is refused outside them, so this can't be bypassed by linking to the proxy directly.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="ttm_ip_header">Visitor IP source</label></th>
                        <td>
                            <select id="ttm_ip_header" name="<?php echo esc_attr(self::OPTION_KEY); ?>[ip_header]">
                                <option value="remote_addr" <?php selected($settings['ip_header'], 'remote_addr'); ?>>Direct connection (REMOTE_ADDR) - most cPanel/VPS hosting</option>
                                <option value="cf_connecting_ip" <?php selected($settings['ip_header'], 'cf_connecting_ip'); ?>>Behind Cloudflare (CF-Connecting-IP)</option>
                                <option value="x_forwarded_for" <?php selected($settings['ip_header'], 'x_forwarded_for'); ?>>Behind another reverse proxy (X-Forwarded-For)</option>
                            </select>
                            <p class="description">
                                Only change this if the site sits behind a CDN/proxy that overwrites this header before
                                requests reach WordPress. Otherwise a visitor can forge it and bypass the IP restriction above.
                                If unsure, leave this on the default.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Check proxy registry</th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr(self::OPTION_KEY); ?>[verify_remote_status]"
                                    value="1" <?php checked($settings['verify_remote_status'], '1'); ?>>
                                Hide the button automatically if this site is disabled in the proxy's <code>sites.json</code>
                            </label>
                            <p class="description">Adds a cached (5 minute) status check to the proxy. If the proxy is unreachable the button still shows.</p>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>
        </div>
        <?php
    }
}
