<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registers a "Site Manager" role: every administrator capability except
 * core/plugin/theme updates, plugin management, theme management, and ACF /
 * ACF Extended settings.
 *
 * ACF and ACF Extended both gate their admin screens behind a single
 * capability filter (default 'manage_options'), so removing manage_options
 * itself would also lock this role out of every other Settings page. Instead
 * we re-point that filter at a dedicated capability (CAP_MANAGE_ACF) that
 * only administrators get - Site Managers simply never receive it.
 *
 * Runs a self-healing sync on 'init' rather than only on activation, since
 * this plugin self-updates across ~80 sites (see TTM_Entra_SSO_Updater) and
 * a fleet-wide capability change needs to reach sites that never get their
 * activation hook re-run. Bump ROLE_VERSION to push a capability change to
 * every site on their next page load.
 */
final class TTM_Entra_SSO_Roles
{
    public const ROLE_SLUG = 'ttm_site_manager';
    public const CAP_MANAGE_ACF = 'manage_acf_settings';

    private const ROLE_NAME = 'Site Manager';
    private const ROLE_VERSION_OPTION = 'ttm_entra_sso_role_version';
    private const ROLE_VERSION = 1;

    public static function init(): void
    {
        add_action('init', [self::class, 'maybe_sync_role']);
        add_filter('acf/settings/capability', [self::class, 'acf_capability']);
        add_filter('acfe/settings/capability', [self::class, 'acf_capability']);
    }

    public static function activate(): void
    {
        self::sync_role();
    }

    public static function maybe_sync_role(): void
    {
        if ((int) get_option(self::ROLE_VERSION_OPTION, 0) < self::ROLE_VERSION) {
            self::sync_role();
        }
    }

    public static function acf_capability(): string
    {
        return self::CAP_MANAGE_ACF;
    }

    private static function sync_role(): void
    {
        $administrator = get_role('administrator');
        if ($administrator === null) {
            return;
        }

        // Only administrators can reach ACF / ACF Extended settings now that
        // their capability filters point at CAP_MANAGE_ACF instead of
        // manage_options.
        $administrator->add_cap(self::CAP_MANAGE_ACF);

        $capabilities = $administrator->capabilities;
        foreach (self::excluded_capabilities() as $cap) {
            unset($capabilities[$cap]);
        }

        remove_role(self::ROLE_SLUG);
        add_role(self::ROLE_SLUG, self::ROLE_NAME, $capabilities);

        update_option(self::ROLE_VERSION_OPTION, self::ROLE_VERSION, false);
    }

    /**
     * @return string[]
     */
    private static function excluded_capabilities(): array
    {
        return [
            self::CAP_MANAGE_ACF,
            // Core / translation updates.
            'update_core',
            'install_languages',
            'update_languages',
            // Plugin management.
            'activate_plugins',
            'edit_plugins',
            'install_plugins',
            'update_plugins',
            'delete_plugins',
            // Theme management.
            'switch_themes',
            'edit_themes',
            'install_themes',
            'update_themes',
            'delete_themes',
        ];
    }
}
