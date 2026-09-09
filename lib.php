<?php
/**
 * Copyright (C) 2026 Kyle Tuck
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Helper functions for Canvas PHP Live Events Processor.
 */

require_once("config.php");

// ─── JWT Extraction ───────────────────────────────────────────────────────────

/**
 * Extract the JWT from the incoming request.
 *
 * Canvas Live Events (HTTPS transport) can deliver the JWT in one of
 * the following ways — this function handles all of them in order:
 *
 *   1. Raw POST body IS the JWT (most common for Live Events HTTPS transport)
 *   2. Authorization: Bearer <token> header
 *   3. JSON body with a `token` or `jwt` field: {"token": "<jwt>"}
 *
 * @param  string $rawBody  Raw POST body
 * @return string           JWT string (header.payload.signature)
 * @throws AuthException
 */
function extractJwt(string $rawBody): string
{
	$trimmed = trim($rawBody, " '\"");

    // Option 1: Raw body is the JWT (three Base64URL segments separated by dots)
    if (isJwt($trimmed)) {
        logMessage('JWT extracted from raw POST body', DEBUG_MODE);
        return $trimmed;
    }

    // Option 2: Authorization: Bearer <token> header
    $authHeader = $_SERVER['HTTP_AUTHORIZATION']
        ?? (function_exists('apache_request_headers') ? (apache_request_headers()['Authorization'] ?? '') : '');

    if (!empty($authHeader) && preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
        $candidate = trim($matches[1]);
        if (isJwt($candidate)) {
            logMessage('JWT extracted from Authorization header', DEBUG_MODE);
            return $candidate;
        }
    }

    // Option 3: JSON body with a token/jwt field
    $decoded = json_decode($trimmed, true);
    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
        foreach (['token', 'jwt', 'access_token'] as $field) {
            if (!empty($decoded[$field]) && isJwt($decoded[$field])) {
                logMessage("JWT extracted from JSON body field: {$field}", DEBUG_MODE);
                return $decoded[$field];
            }
        }
    }

    // Nothing found — log what was actually received to help diagnose
    logMessage('Could not locate a JWT. Raw body (first 500 chars): ' . substr($trimmed, 0, 500));
    logMessage('Headers received: ' . json_encode(getallheaders()));

    throw new AuthException(
        'Could not locate JWT in request. Expected: raw JWT body, Authorization header, ' .
        'or JSON body with a "token" field. Check logs for raw request details.'
    );
}

/**
 * Check whether a string looks like a JWT (three dot-separated Base64URL segments).
 */
function isJwt(string $value): bool
{
    return (bool) preg_match('/^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$/', $value);
}

// ─── JWT Validation ───────────────────────────────────────────────────────────

/**
 * Validate a JWT signed with RS256 using a JWKS endpoint.
 *
 * Steps:
 *   1. Decode the JWT header to extract `kid` (Key ID) and `alg`
 *   2. Fetch the JWKS (from cache or remote)
 *   3. Find the matching JWK by `kid`
 *   4. Convert the JWK to a PEM public key
 *   5. Verify the RS256 signature
 *   6. Validate standard claims (exp, nbf, iss)
 *
 * @param  string $jwt  Raw JWT string
 * @return array        Decoded claims from the JWT payload
 * @throws AuthException
 */
function validateJwt(string $jwt): array
{
    $parts = explode('.', $jwt);
    if (count($parts) !== 3) {
        throw new AuthException('Invalid JWT structure — expected 3 dot-separated parts');
    }

    [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

    // Decode JWT header
    $header = json_decode(base64UrlDecode($encodedHeader), true);
    if (!$header || json_last_error() !== JSON_ERROR_NONE) {
        throw new AuthException('Failed to decode JWT header');
    }

    // Enforce RS256 — prevents algorithm confusion (none/HS256) attacks
    $alg = strtoupper($header['alg'] ?? '');
    if ($alg !== ALLOWED_ALGORITHM) {
        throw new AuthException("Unsuppord JWT algorithm: {$alg}. Expected: " . ALLOWED_ALGORITHM);
    }

    // Extract `kid` to select the correct public key from JWKS
    $kid = $header['kid'] ?? null;
    if (empty($kid)) {
        throw new AuthException('JWT header is missing `kid` (Key ID)');
    }

    // Fetch JWKS and locate matching key
    $jwks  = fetchJwks();
    $jwk   = findJwkByKid($jwks, $kid);
    $pubKey = jwkToPem($jwk);

    // Verify signature
    $signingInput = $encodedHeader . "." . $encodedPayload;
    $signature    = base64UrlDecode($encodedSignature);

    $verifyResult = openssl_verify($signingInput, $signature, $pubKey, OPENSSL_ALGO_SHA256);

    if ($verifyResult === -1) {
        throw new AuthException('OpenSSL error during verification: ' . openssl_error_string());
    }
    if ($verifyResult !== 1) {
        throw new AuthException('JWT signature verification failed — token may be tampered or signed with an unknown key');
    }

    // Decode payload claims
    $claims = json_decode(base64UrlDecode($encodedPayload), true);
    if (!$claims || json_last_error() !== JSON_ERROR_NONE) {
        throw new AuthException('Failed to decode JWT payload claims');
    }

    // Validate expiration
    if (isset($claims['exp']) && time() > (int)$claims['exp']) {
        throw new AuthException('JWT has expired (exp: ' . $claims['exp'] . ')');
    }

    // Validate not-before
    if (isset($claims['nbf']) && time() < (int)$claims['nbf']) {
        throw new Authception('JWT not yet valid (nbf: ' . $claims['nbf'] . ')');
    }

    // Validate issuer
    if (!empty(ALLOWED_ISSUERS) && isset($claims['iss'])) {
        if (!in_array($claims['iss'], ALLOWED_ISSUERS, true)) {
            throw new AuthException("Untrusted JWT issuer: {$claims['iss']}");
        }
    }

    return $claims;
}

// ─── JWKS Functions ───────────────────────────────────────────────────────────

/**
 * Fetch the JWKS from Canvas, using a local file cache.
 *
 * @param  bool  $bypassCache  Force a fresh fetch (used on key rotation)
 * @return array               Decoded JWKS with a `keys` array
 * @throws AuthException
 */
function fetchJwks(bool $bypassCache = false): array
{
    $cacheFile = JWKS_CACHE_PATH;

    if (!$bypassCache && file_exists($cacheFile)) {
        $age = time() - filemtime($cacheFile);
        if ($age < JWKS_CACHE_TTL) {
            $cached = json_decode(file_get_contents($cacheFile), true);
            if (!empty($cached['keys'])) {
                logMessage('JWKS loaded from cache (age: ' . $age . 's)', DEBUG_MODE);
                return $cached;
            }
        }
    }

    logMessage('Fetching JWKS from: ' . JWKS_URL, DEBUG_MODE);

    $ch = curl_init(JWKS_URL);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => JWKS_FETCH_TIMEOUT,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_HTTPHEADER     => ['Accept: application/json', 'User-Agent: UkyLiveEvents/1.0 (elearning@uky.edu)'],
    ]);

    $response  = curl_exec($ch);
    $httpCode  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        throw new AuthException("Failed to fetch JWKS (cURL error): {$curlError}");
    }
    if ($httpCode !== 200) {
        throw new AuthException("Failed to fetch JWKS — HTTP {$httpCode} from: " . JWKS_URL);
    }

    $jwks = json_decode($response, true);
    if (!$jwks || empty($jwks['keys'])) {
        throw new AuthException('Invalid or empty JWKS response from Canvas');
    }

    file_put_contents($cacheFile, json_encode($jwks), LOCK_EX);
    logMessage('JWKS cached successfully (' . count($jwks['keys']) . ' key(s))', DEBUG_MODE);

    return $jwks;
}

/**
 * Find a JWK by `kid`. On miss, bypass cache once to handle key rotation.
 *
 * @throws AuthException if key is not found even after refresh
 */
function findJwkByKid(array $jwks, string $kid): array
{
    foreach ($jwks['keys'] as $key) {
        if (isset($key['kid']) && $key['kid'] === $kid) {
            return $key;
        }
    }

    logMessage("kid '{$kid}' not in cached JWKS — refreshing from Canvas", DEBUG_MODE);
    $fresh = fetchJwks(bypassCache: true);

    foreach ($fresh['keys'] as $key) {
        if (isset($key['kid']) && $key['kid'] === $kid) {
            return $key;
        }
    }

    throw new AuthException("No matching JWK found for kid: {$kid}");
}

/**
 * Convert a JWK (RSA) to a PEM public key for use with openssl_verify().
 *
 * @throws AuthException
 */
function jwkToPem(array $jwk)
{
    if (($jwk['kty'] ?? '') !== 'RSA') {
        throw new AuthException("Unsupported JWK key type: " . ($jwk['kty'] ?? 'unknown'));
    }
    if (empty($jwk['n']) || empty($jwk['e'])) {
        throw new AuthException('JWK missing required RSA fields (n, e)');
    }

    $modulus  = base64UrlDecode($jwk['n']);
    $exponent = base64UrlDecode($jwk['e']);

    $pem = buildPemFromComponents($modulus, $exponent);
    $key = openssl_pkey_get_public($pem);

    if ($key === false) {
        throw new AuthException('Failed to load RSA public key from JWK: ' . openssl_error_string());
    }

    return $key;
}

/**
 * Build a PEM-encoded SubjectPublicKeyInfo from raw RSA modulus + exponent bytes.
 */
function buildPemFromComponents(string $modulus, string $exponent): string
{
    if (ord($modulus[0]) > 0x7f) {
        $modulus = "\x00" . $modulus;
    }

    $modAsn  = "\x02" . encodeLength(strlen($modulus)) . $modulus;
    $expAsn  = "\x02" . encodeLength(strlen($exponent)) . $exponent;
    $seqBody = $modAsn . $expAsn;
    $seq     = "\x30" . encodeLength(strlen($seqBody)) . $seqBody;
    $bitStr  = "\x03" . encodeLength(strlen($seq) + 1) . "\x00" . $seq;
    $rsaOid  = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $spki    = "\x30" . encodeLength(strlen($rsaOid) + strlen($bitStr)) . $rsaOid . $bitStr;

    return "-----BEGIN PUBLIC KEY-----\n"
        . chunk_split(base64_encode($spki), 64, "\n")
        . "-----END PUBLIC KEY-----\n";
}

/**
 * DER-encode a length value (ASN.1).
 */
function encodeLength(int $length): string
{
    if ($length < 0x80) {
        return chr($length);
    }
    $temp = ltrim(pack('N', $length), "\x00");
    return chr(0x80 | strlen($temp)) . $temp;
}

// ─── Event Processing ─────────────────────────────────────────────────────────

/**
 * Process the Canvas Live Event from validated JWT claims.
 *
 * Canvas embeds the event type and data directly in the JWT payload claims.
 * Common claim keys:
 *   - event_type / type / @type  — the Canvas event type name
 *   - data                       — the event body (varies by event)
 *
 * @param array $claims  Validated JWT payload claims
 */
function processEvent(array $claims): void
{
    $eventType = $claims['metadata']['event_name']
        ?? $claims['type']
        ?? $claims['@type']
        ?? 'unknown';

    logMessage("Processing event: {$eventType}", DEBUG_MODE);
	
	// check if this event has defined handlers
	$handlerClasses = [];
	$handled = false;

	if (array_key_exists($eventType, EVENT_HANDLERS)) {
		if (is_array(EVENT_HANDLERS[$eventType])) {
			foreach (EVENT_HANDLERS[$eventType] as $handler) {
				// Allow only safe filename characters
				$handlerClassFileName = "./handlers/" . preg_replace('/[^A-Za-z0-9_-]/', '', $handler) . ".php";
				$handlerClasses[$handler] = $handlerClassFileName;
			}
		} else {
			$handlerClass = EVENT_HANDLERS[$eventType];
			// Allow only safe filename characters
			$handlerClassFileName = "./handlers/" . preg_replace('/[^A-Za-z0-9_-]/', '', $handlerClass) . ".php";
			$handlerClasses[$handlerClass] = $handlerClassFileName;
		}
	}

	foreach ($handlerClasses as $handlerClass => $handlerClassFileName) {
		if (file_exists($handlerClassFileName)) {
			require_once($handlerClassFileName);
			if (class_exists($handlerClass)) {
				$handler = new $handlerClass();
				$handler->handle($claims);
				$handled = true;
			} else {
				logMessage("handlerClass " . $handlerClass . " does not exist.");
			}
		} else {
			logMessage("handler file not found: " . $handlerClassFileName);
		}
	}
	
	if ($handled) return;

	logMessage("Unhandled event type: {$eventType}");
	logEvent($claims);
}

// ─── Debug Helper ─────────────────────────────────────────────────────────────

/**
 * Dump all headers and the raw body to the log.
 * Enable by setting DEBUG_MODE = true in the config file.
 * Disable in production — this will log sensitive JWT data.
 */
function debugDump(string $rawBody): void
{
    $headers = function_exists('getallheaders') ? getallheaders() : [];
    logMessage('DEBUG HEADERS: ' . json_encode($headers, JSON_PRETTY_PRINT));
    logMessage('DEBUG RAW BODY (first 1000 chars): ' . substr($rawBody, 0, 1000));
}

// ─── Utilities ────────────────────────────────────────────────────────────────

function base64UrlDecode(string $input): string
{
    $base64 = strtr($input, '-_', '+/');
    $padded = str_pad($base64, strlen($base64) + (4 - strlen($base64) % 4) % 4, '=');
    return base64_decode($padded);
}

function logMessage(string $message, $log_it = true): void
{
	if ($log_it) {
		$timestamp = date('Y-m-d H:i:s');
		$ip        = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
		file_put_contents(LOG_PATH, "[{$timestamp}] [{$ip}] {$message}" . PHP_EOL, FILE_APPEND | LOCK_EX);
	}
}

function logEvent(array $data): void
{
    logMessage('DATA: ' . json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
}

// ─── Custom Exceptions ────────────────────────────────────────────────────────

class AuthException extends RuntimeException {}