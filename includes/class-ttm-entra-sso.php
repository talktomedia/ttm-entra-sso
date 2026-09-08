<?php

declare( strict_types=1 );

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Login button + REST callback that verifies the proxy's handoff token and
 * logs the matching (or newly created) WordPress user in.
 */
final class TTM_Entra_SSO {
	private const REST_NAMESPACE = 'ttm-entra-sso/v1';
	private const REPLAY_CACHE_GROUP = 'ttm_entra_sso_jti';

	/**
	 * The proxy is itself a WordPress plugin (see mainwp-plugin/ttm-entra-sso-proxy)
	 * exposing these fixed REST paths under its own site's base URL.
	 */
	private const PROXY_REST_NAMESPACE = 'ttm-entra-sso-proxy/v1';

	public static function init(): void {
		add_action( 'login_form', [ self::class, 'render_login_button' ] );
		add_filter( 'login_message', [ self::class, 'render_login_error' ] );
		add_action( 'rest_api_init', [ self::class, 'register_routes' ] );
	}

	public static function render_login_error( string $message ): string {
		if ( empty( $_GET['ttm_sso_error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return $message;
		}

		$error = sanitize_text_field( wp_unslash( (string) $_GET['ttm_sso_error'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		return $message . sprintf(
				'<div id="login_error">%s</div>',
				esc_html( $error )
			);
	}

	public static function render_login_button(): void {
		$settings = TTM_Entra_SSO_Settings::get();

		if ( empty( $settings['proxy_url'] ) || empty( $settings['site_id'] ) || empty( $settings['shared_secret'] ) ) {
			return; // Not configured yet - don't show a dead button.
		}

		$client_ip = TTM_Entra_SSO_Ip::client_ip( $settings['ip_header'] );
		if ( ! TTM_Entra_SSO_Ip::is_allowed( $client_ip, $settings['allowed_ips'] ) ) {
			return; // Outside the configured IP allowlist - don't show the button at all.
		}

		if ( ! self::is_enabled_remotely( $settings ) ) {
			return; // This site has been disabled in the proxy's registry.
		}

		$redirect_to = isset( $_GET['redirect_to'] ) ? wp_unslash( (string) $_GET['redirect_to'] ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$url = add_query_arg(
			array_filter( [
				'site_id' => $settings['site_id'],
				'context' => $redirect_to !== '' ? rawurlencode( $redirect_to ) : NULL,
			] ),
			self::proxy_endpoint( $settings['proxy_url'], 'authorize' )
		);

		printf(
			'<p style="text-align:center;margin-bottom:1em;">%s</p><p style="margin-bottom:1em;"><a href="%s" class="button button-primary button-large" style="float:none;width:100%%;text-align:center;display:inline-flex;align-items:center"><svg xmlns="http://www.w3.org/2000/svg" width="21" height="21" viewBox="0 0 21 21" style="margin-right:1em;"><title>MS-SymbolLockup</title><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>%s</a></p>',
			__( '<b>Talk To Media Staff</b><br> Sign in with your Microsoft Account', 'ttm-entra-sso' ),
			esc_url( $url ),
			esc_html__( 'Sign in with Microsoft', 'ttm-entra-sso' ),
		);
	}

	/**
	 * Builds a URL to one of the proxy's REST routes. $proxy_url is just
	 * that site's base URL (e.g. https://dashboard.talktomedia.co.uk) -
	 * the /wp-json/... path is fixed, so nobody has to remember or retype it
	 * per client site.
	 */
	private static function proxy_endpoint( string $proxy_url, string $path ): string {
		return untrailingslashit( $proxy_url ) . '/wp-json/' . self::PROXY_REST_NAMESPACE . '/' . $path;
	}

	public static function register_routes(): void {
		register_rest_route( self::REST_NAMESPACE, '/callback', [
			'methods'             => 'GET',
			'callback'            => [ self::class, 'handle_callback' ],
			'permission_callback' => '__return_true',
			'args'                => [
				'token' => [
					'required' => TRUE,
					'type'     => 'string',
				],
			],
		] );
	}

	/**
	 * Always exits: either via a wp_safe_redirect into the site on success,
	 * or via self::fail() on any verification failure. Declared to return a
	 * value only to satisfy the REST route callback signature.
	 *
	 * @return void
	 */
	public static function handle_callback( WP_REST_Request $request ) {
		$settings = TTM_Entra_SSO_Settings::get();

		if ( empty( $settings['shared_secret'] ) || empty( $settings['site_id'] ) ) {
			self::fail( 'SSO is not configured on this site.' );
		}

		// Enforced here, not just at the button - hiding the button is UX,
		// this is the actual access control. Otherwise someone outside the
		// allowlist could still complete a login by going straight to the
		// proxy's authorize URL and landing back here with a valid token.
		$client_ip = TTM_Entra_SSO_Ip::client_ip( $settings['ip_header'] );
		if ( ! TTM_Entra_SSO_Ip::is_allowed( $client_ip, $settings['allowed_ips'] ) ) {
			self::fail( 'This sign-in method is not available from your current location.' );
		}

		try {
			$claims = TTM_Entra_SSO_Jwt::decode( (string) $request->get_param( 'token' ), $settings['shared_secret'] );
		} catch ( RuntimeException $e ) {
			self::fail( 'Sign-in link is invalid or expired.' );
		}

		if ( ( $claims['iss'] ?? NULL ) !== 'ttm-entra-sso-proxy' ) {
			self::fail( 'Sign-in link has an unexpected issuer.' );
		}

		if ( ( $claims['site_id'] ?? NULL ) !== $settings['site_id'] ) {
			self::fail( 'Sign-in link was issued for a different site.' );
		}

		$jti = (string) ( $claims['jti'] ?? '' );
		if ( $jti === '' || self::jti_already_used( $jti ) ) {
			self::fail( 'Sign-in link has already been used.' );
		}
		self::mark_jti_used( $jti, (int) ( $claims['exp'] ?? time() + 120 ) );

		$email = sanitize_email( (string) ( $claims['email'] ?? '' ) );
		if ( $email === '' || ! is_email( $email ) ) {
			self::fail( 'Sign-in did not return a usable email address.' );
		}

		if ( ! empty( $settings['allowed_email_domain'] ) ) {
			$domain = strtolower( substr( strrchr( $email, '@' ) ?: '', 1 ) );
			if ( $domain !== strtolower( $settings['allowed_email_domain'] ) ) {
				self::fail( 'This account is not permitted to sign in to this site.' );
			}
		}

		$user = get_user_by( 'email', $email );

		if ( ! $user ) {
			if ( empty( $settings['auto_create_users'] ) ) {
				self::fail( 'No account exists for this email address.' );
			}
			$user = self::create_user(
				$email,
				(string) ( $claims['given_name'] ?? '' ),
				(string) ( $claims['family_name'] ?? '' ),
				(string) ( $claims['name'] ?? '' ),
				$settings['default_role'],
				! empty( $claims['force_admin'] )
			);
			if ( is_wp_error( $user ) ) {
				self::fail( 'Could not create an account: ' . $user->get_error_message() );
			}
		}

		wp_set_current_user( $user->ID );
		wp_set_auth_cookie( $user->ID, TRUE );
		do_action( 'wp_login', $user->user_login, $user );

		$redirect = ! empty( $claims['context'] )
			? rawurldecode( (string) $claims['context'] )
			: $settings['redirect_after_login'];

		wp_safe_redirect( $redirect );
		exit;
	}

	/**
	 * @return WP_User|WP_Error
	 */
	private static function create_user( string $email, string $given_name, string $family_name, string $full_name, string $role, bool $force_admin ) {
		$username     = self::unique_username( $given_name, $family_name, $email );
		$display_name = self::display_name( $given_name, $family_name, $full_name, $username );

		$user_id = wp_insert_user( [
			'user_login'   => $username,
			'user_email'   => $email,
			'user_pass'    => wp_generate_password( 32, TRUE, TRUE ),
			'first_name'   => $given_name,
			'last_name'    => $family_name,
			'display_name' => $display_name,
			'role'         => $force_admin ? 'administrator' : $role,
		] );

		if ( is_wp_error( $user_id ) ) {
			return $user_id;
		}

		return get_user_by( 'id', $user_id );
	}

	/**
	 * "Jane Doe" -> "jdoe", falling back to the email's local part if
	 * Entra didn't return given_name/family_name (e.g. a guest account with
	 * an incomplete profile) - same de-duplication behaviour either way.
	 */
	private static function unique_username( string $given_name, string $family_name, string $email ): string {
		$base = '';

		if ( $given_name !== '' && $family_name !== '' ) {
			$base = sanitize_user( substr( $given_name, 0, 1 ) . preg_replace( '/\s+/', '', $family_name ), TRUE );
		}

		if ( $base === '' ) {
			$base = sanitize_user( substr( $email, 0, (int) strpos( $email, '@' ) ), TRUE );
		}

		$base     = strtolower( $base !== '' ? $base : 'user' );
		$username = $base;
		$suffix   = 1;

		while ( username_exists( $username ) ) {
			$username = $base . $suffix;
			$suffix ++;
		}

		return $username;
	}

	private static function display_name( string $given_name, string $family_name, string $full_name, string $fallback ): string {
		if ( $given_name !== '' || $family_name !== '' ) {
			return trim( $given_name . ' ' . $family_name );
		}

		return $full_name !== '' ? $full_name : $fallback;
	}

	/**
	 * Asks the proxy whether this site is still enabled in its registry, so
	 * the button disappears on its own if a site gets switched off there
	 * (e.g. an offboarded client) without having to also touch this site's
	 * settings. Opt-in, cached, and fails open - a proxy that's slow or
	 * temporarily down shouldn't take the login button with it, since the
	 * actual sign-in flow already depends on the proxy being reachable.
	 */
	private static function is_enabled_remotely( array $settings ): bool {
		if ( empty( $settings['verify_remote_status'] ) ) {
			return TRUE;
		}

		$cache_key = 'ttm_sso_enabled_' . md5( $settings['proxy_url'] . '|' . $settings['site_id'] );
		$cached    = get_transient( $cache_key );
		if ( $cached !== FALSE ) {
			return $cached === '1';
		}

		$response = wp_remote_get(
			add_query_arg( 'site_id', rawurlencode( $settings['site_id'] ), self::proxy_endpoint( $settings['proxy_url'], 'status' ) ),
			[ 'timeout' => 3 ]
		);

		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			// Fail open on the button, but don't hammer a down/slow proxy on every page load.
			set_transient( $cache_key, '1', 60 );

			return TRUE;
		}

		$body    = json_decode( wp_remote_retrieve_body( $response ), TRUE );
		$enabled = is_array( $body ) && ! empty( $body['enabled'] );

		set_transient( $cache_key, $enabled ? '1' : '0', 300 );

		return $enabled;
	}

	/**
	 * Replay protection for the short-lived handoff token: once a jti has
	 * been redeemed it can't be redeemed again, even within its TTL.
	 */
	private static function jti_already_used( string $jti ): bool {
		return get_transient( self::transient_key( $jti ) ) !== FALSE;
	}

	private static function mark_jti_used( string $jti, int $expires_at ): void {
		$ttl = max( 1, $expires_at - time() + 30 ); // small buffer over the token's own expiry
		set_transient( self::transient_key( $jti ), 1, $ttl );
	}

	private static function transient_key( string $jti ): string {
		return self::REPLAY_CACHE_GROUP . '_' . md5( $jti );
	}

	/**
	 * Sends the user back to wp-login.php with a friendly error, rather than
	 * a raw REST JSON error. Never returns.
	 *
	 * @return never
	 */
	private static function fail( string $message ): void {
		error_log( '[ttm-entra-sso] ' . $message );
		wp_safe_redirect( add_query_arg( 'ttm_sso_error', rawurlencode( $message ), wp_login_url() ) );
		exit;
	}
}
