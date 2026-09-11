<?php
/**
 * Plugin Name: TTM Entra ID SSO
 * Description: Adds "Sign in with Microsoft" login via TTM's central Entra ID SSO proxy. One shared secret per site, no client secrets stored on this server.
 * Version: 1.2.14
 * Author: Talk To Media
 * Requires PHP: 7.4
 * License: Proprietary - internal TTM use across client sites
 * Update URI: https://github.com/talktomedia/ttm-entra-sso
 *
 * @package TtmEntraSso
 */

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit; // No direct access.
}

define('TTM_ENTRA_SSO_VERSION', '1.2.14');
define('TTM_ENTRA_SSO_DIR', plugin_dir_path(__FILE__));
define('TTM_ENTRA_SSO_URL', plugin_dir_url(__FILE__));
define('TTM_ENTRA_SSO_GITHUB_REPO', 'talktomedia/ttm-entra-sso');

require_once TTM_ENTRA_SSO_DIR . 'includes/class-ttm-jwt.php';
require_once TTM_ENTRA_SSO_DIR . 'includes/class-ttm-entra-sso-ip.php';
require_once TTM_ENTRA_SSO_DIR . 'includes/class-ttm-entra-sso-settings.php';
require_once TTM_ENTRA_SSO_DIR . 'includes/class-ttm-entra-sso-roles.php';
require_once TTM_ENTRA_SSO_DIR . 'includes/class-ttm-entra-sso.php';
require_once TTM_ENTRA_SSO_DIR . 'includes/class-ttm-entra-sso-updater.php';

add_action('plugins_loaded', static function (): void {
    TTM_Entra_SSO_Settings::init();
    TTM_Entra_SSO_Roles::init();
    TTM_Entra_SSO::init();
    TTM_Entra_SSO_Updater::init(__FILE__, TTM_ENTRA_SSO_GITHUB_REPO, TTM_ENTRA_SSO_VERSION);
});

register_activation_hook(__FILE__, static function (): void {
    TTM_Entra_SSO_Roles::activate();
});
