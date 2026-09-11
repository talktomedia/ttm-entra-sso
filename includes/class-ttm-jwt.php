<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    exit;
}

/**
 * Minimal HS256 JWT verifier - the plugin-side counterpart to the proxy's
 * Jwt class. This side only ever needs to *verify*, since the proxy is the
 * only thing that signs. Keep the verification logic identical to the
 * proxy's Jwt::decode().
 */
final class TTM_Entra_SSO_Jwt
{
    /**
     * @return array<string, mixed>
     * @throws RuntimeException on any verification failure.
     */
    public static function decode(string $jwt, string $secret): array
    {
        $parts = explode('.', $jwt);

        if (count($parts) !== 3) {
            throw new RuntimeException('Malformed token.');
        }

        list($header, $payload, $signature) = $parts;

        $expected = self::base64UrlEncode(hash_hmac('sha256', "{$header}.{$payload}", $secret, true));

        if (!hash_equals($expected, $signature)) {
            throw new RuntimeException('Token signature verification failed.');
        }

        $decodedHeader = json_decode(self::base64UrlDecode($header), true);
        if (!is_array($decodedHeader) || ($decodedHeader['alg'] ?? null) !== 'HS256') {
            throw new RuntimeException('Unsupported or missing token algorithm.');
        }

        $claims = json_decode(self::base64UrlDecode($payload), true);
        if (!is_array($claims)) {
            throw new RuntimeException('Malformed token payload.');
        }

        $now = time();

        if (isset($claims['exp']) && $now >= (int) $claims['exp']) {
            throw new RuntimeException('Token has expired.');
        }

        if (isset($claims['nbf']) && $now < (int) $claims['nbf']) {
            throw new RuntimeException('Token is not yet valid.');
        }

        return $claims;
    }

    private static function base64UrlEncode(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        $padded = $remainder ? str_pad($data, strlen($data) + 4 - $remainder, '=') : $data;

        $decoded = base64_decode(strtr($padded, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }
}
