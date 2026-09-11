<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * IP allowlist matching for the "only show/allow this from the office" case.
 *
 * Kept free of WordPress function calls (except in client_ip(), which reads
 * $_SERVER directly) so the matching logic itself is trivially unit-testable
 * outside WordPress.
 */
final class TTM_Entra_SSO_Ip
{
    /**
     * @param string $header Which value to trust as the visitor's real IP:
     *                       'remote_addr' (default - correct for direct/cPanel
     *                       hosting with no CDN in front), 'cf_connecting_ip'
     *                       (Cloudflare), or 'x_forwarded_for' (generic reverse
     *                       proxy - only safe if something in front of PHP
     *                       strips/overwrites any client-supplied value first).
     */
    public static function client_ip(string $header): string
    {
        switch ($header) {
            case 'cf_connecting_ip':
                $ip = self::server_value('HTTP_CF_CONNECTING_IP');
                return $ip !== '' ? $ip : self::server_value('REMOTE_ADDR');

            case 'x_forwarded_for':
                $xff = self::server_value('HTTP_X_FORWARDED_FOR');
                if ($xff !== '') {
                    $parts = explode(',', $xff);
                    return trim($parts[0]);
                }
                return self::server_value('REMOTE_ADDR');

            case 'remote_addr':
            default:
                return self::server_value('REMOTE_ADDR');
        }
    }

    private static function server_value(string $key): string
    {
        return isset($_SERVER[$key]) ? trim((string) $_SERVER[$key]) : '';
    }

    /**
     * @param string $allowedList Comma and/or newline separated list of exact
     *                             IPs and/or IPv4 CIDR ranges (e.g.
     *                             "203.0.113.10, 198.51.100.0/24").
     */
    public static function is_allowed(string $ip, string $allowedList): bool
    {
        if (trim($allowedList) === '') {
            return true; // Not configured - no restriction.
        }

        if ($ip === '') {
            return false; // Restriction configured but we couldn't determine an IP - fail closed.
        }

        foreach (preg_split('/[\s,]+/', $allowedList, -1, PREG_SPLIT_NO_EMPTY) ?: [] as $entry) {
            if (self::ip_matches($ip, trim($entry))) {
                return true;
            }
        }

        return false;
    }

    public static function ip_matches(string $ip, string $entry): bool
    {
        if ($entry === '') {
            return false;
        }

        if (strpos($entry, '/') === false) {
            return $entry === $ip;
        }

        list($subnet, $bits) = explode('/', $entry, 2);

        if (!ctype_digit($bits)) {
            return false;
        }

        $bits = (int) $bits;

        if ($bits < 0 || $bits > 32) {
            return false;
        }

        if (!filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) || !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false; // IPv6 CIDR ranges aren't supported - use an exact IPv6 entry instead.
        }

        $mask = ($bits === 0) ? 0 : ((~0 << (32 - $bits)) & 0xFFFFFFFF);

        $ipLong = ip2long($ip);
        $subnetLong = ip2long($subnet);

        if ($ipLong === false || $subnetLong === false) {
            return false;
        }

        return ($ipLong & $mask) === ($subnetLong & $mask);
    }
}
