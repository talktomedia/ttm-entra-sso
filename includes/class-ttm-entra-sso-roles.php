<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Registers TTM's custom roles on top of WordPress's defaults:
 *
 * - Site Manager: every administrator capability except core/plugin/theme
 *   updates, plugin management, theme management, and ACF / ACF Extended
 *   settings (see CAP_MANAGE_ACF below).
 * - Site Editor: every editor capability plus access to Yoast SEO, Rank
 *   Math, and WooCommerce's admin screens.
 *
 * ACF and ACF Extended gate their whole admin UI behind a single
 * capability filter (default 'manage_options'), so removing manage_options
 * itself from Site Manager would also lock it out of every other Settings
 * page. Instead that filter is re-pointed at a dedicated capability
 * (CAP_MANAGE_ACF) that only administrators receive.
 *
 * Yoast SEO and Rank Math both namespace their own capabilities
 * ('wpseo_*' / 'rank_math_*'), so Site Editor is granted those wholesale
 * via a user_has_cap filter rather than an enumerated, version-fragile
 * list. WooCommerce doesn't follow that convention, so Site Editor's
 * capabilities instead mirror whatever WooCommerce's own 'shop_manager'
 * role defines at sync time - authoritative for whatever WooCommerce
 * version is actually installed, no guessing required.
 *
 * Both roles are synced on 'init' (versioned, not just on activation)
 * since this plugin self-updates across ~80 sites (see
 * TTM_Entra_SSO_Updater) and a fleet-wide capability change needs to reach
 * sites that never get their activation hook re-run. Bump ROLE_VERSION to
 * push a capability change to every site on their next page load. Site
 * Editor is also re-synced whenever WooCommerce itself is activated, so
 * sites that install WooCommerce after this plugin don't have to wait for
 * an unrelated version bump to pick up its capabilities.
 */
final class TTM_Entra_SSO_Roles
{
    public const SITE_MANAGER_SLUG = 'ttm_site_manager';
    public const SITE_EDITOR_SLUG = 'ttm_site_editor';
    public const CAP_MANAGE_ACF = 'manage_acf_settings';

    private const SITE_MANAGER_NAME = 'Site Manager';
    private const SITE_EDITOR_NAME = 'Site Editor';
    private const ROLE_VERSION_OPTION = 'ttm_entra_sso_role_version';
    private const ROLE_VERSION = 2;

    /** @var string[] Capability prefixes granted to Site Editor wholesale. */
    private const SITE_EDITOR_CAP_PREFIXES = ['wpseo_', 'rank_math_'];

    public static function init(): void
    {
        add_action('init', [self::class, 'maybe_sync_roles']);
        add_action('activated_plugin', [self::class, 'maybe_sync_on_plugin_activation']);
        add_filter('acf/settings/capability', [self::class, 'acf_capability']);
        add_filter('acfe/settings/capability', [self::class, 'acf_capability']);
        add_filter('user_has_cap', [self::class, 'grant_site_editor_plugin_caps'], 10, 4);
    }

    public static function activate(): void
    {
        self::sync_roles();
    }

    public static function maybe_sync_roles(): void
    {
        if ((int) get_option(self::ROLE_VERSION_OPTION, 0) < self::ROLE_VERSION) {
            self::sync_roles();
        }
    }

    /**
     * WooCommerce's own capabilities only exist once it's active, and it
     * may well be activated on a client site after this plugin already
     * synced its roles once - catch that instead of waiting for the next
     * ROLE_VERSION bump.
     */
    public static function maybe_sync_on_plugin_activation(string $plugin): void
    {
        if (strpos($plugin, 'woocommerce.php') !== false) {
            self::sync_site_editor();
        }
    }

    public static function acf_capability(): string
    {
        return self::CAP_MANAGE_ACF;
    }

    /**
     * Grants Site Editors any 'wpseo_*' (Yoast SEO) or 'rank_math_*' (Rank
     * Math) capability outright - both plugins namespace every one of their
     * own custom capabilities this way, so this covers their settings
     * screens, metaboxes, and bulk tools without hardcoding a capability
     * list that would drift out of date across plugin updates.
     *
     * @param array<string, bool> $allcaps
     * @param string[] $caps
     * @param array<int, mixed> $args
     * @return array<string, bool>
     */
    public static function grant_site_editor_plugin_caps(array $allcaps, array $caps, array $args, WP_User $user): array
    {
        if (!in_array(self::SITE_EDITOR_SLUG, $user->roles, true)) {
            return $allcaps;
        }

        foreach ($caps as $cap) {
            foreach (self::SITE_EDITOR_CAP_PREFIXES as $prefix) {
                if (strncmp($cap, $prefix, strlen($prefix)) === 0) {
                    $allcaps[$cap] = true;
                    break;
                }
            }
        }

        return $allcaps;
    }

    private static function sync_roles(): void
    {
        self::sync_site_manager();
        self::sync_site_editor();

        update_option(self::ROLE_VERSION_OPTION, self::ROLE_VERSION, false);
    }

    private static function sync_site_manager(): void
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
        foreach (self::site_manager_excluded_capabilities() as $cap) {
            unset($capabilities[$cap]);
        }

        remove_role(self::SITE_MANAGER_SLUG);
        add_role(self::SITE_MANAGER_SLUG, self::SITE_MANAGER_NAME, $capabilities);
    }

    private static function sync_site_editor(): void
    {
        $editor = get_role('editor');
        if ($editor === null) {
            return;
        }

        $capabilities = $editor->capabilities;

        // WooCommerce doesn't namespace its capabilities consistently
        // enough to pattern-match (edit_products, edit_shop_orders,
        // manage_woocommerce, ...), so mirror whatever its own
        // 'shop_manager' role currently grants instead of hardcoding a list
        // that would drift across WooCommerce versions. No-op if
        // WooCommerce isn't active.
        $shopManager = get_role('shop_manager');
        if ($shopManager !== null) {
            $capabilities = array_merge($capabilities, $shopManager->capabilities);
        }

        remove_role(self::SITE_EDITOR_SLUG);
        add_role(self::SITE_EDITOR_SLUG, self::SITE_EDITOR_NAME, $capabilities);
    }

    /**
     * @return string[]
     */
    private static function site_manager_excluded_capabilities(): array
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