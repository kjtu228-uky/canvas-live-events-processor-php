<?php

/**
 * Copyright (C) 2026 Kyle Tuck
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Canvas Live Events - JWT-Secured Webhook Receiver (RSA / RS256 via JWKS)
 *
 * This script receives the signed Canvas Live Events, responds to Canvas as quickly as possible, then processes the
 * received event using event handlers.
 *
 * Canvas Admin Setup:
 *   Settings > Data Services > Live Events
 *   Set Delivery Method to HTTPS and point to this script's public URL. Sign Payload must be checked.
 *   The JWKS URL is provided by Canvas in the Live Events Setup page.
 *      https://developerdocs.instructure.com/services/canvas/data-services/live-events/overview/file.data_service_setup
 */

// ─── Configuration ────────────────────────────────────────────────────────────
require_once('config.php');
require_once('lib.php');

// ─── Bootstrap ────────────────────────────────────────────────────────────────

header('Content-Type: application/json');

foreach ([dirname(LOG_PATH), dirname(JWKS_CACHE_PATH)] as $dir) {
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
}

// ─── Main Entry Point ─────────────────────────────────────────────────────────

try {
	// Only accept POST requests
	if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
		http_response_code(405);
		exit(json_encode(['error' => 'Method Not Allowed']));
	}

	// Read the raw POST body — for Canvas Live Events this IS the JWT
	$rawBody = file_get_contents('php://input');

	if (DEBUG_MODE) {
		debugDump($rawBody);
	}

	if (empty($rawBody)) {
		http_response_code(400);
		exit(json_encode(['error' => 'Empty request body']));
	}

	// Extract and validate the JWT
	$jwt = extractJwt($rawBody);
	$claims = validateJwt($jwt);

	// Acknowledge receipt — Canvas expects a 200 response quickly; flush response so Canvas does not wait
	http_response_code(200);
	echo json_encode(['status' => 'received']);
	if (function_exists('fastcgi_finish_request')) fastcgi_finish_request();

	// Process the Canvas event data inside the JWT claims
	processEvent($claims);
} catch (AuthException $e) {
    logMessage('AUTH_ERROR: ' . $e->getMessage());
    http_response_code(401);
    echo json_encode(['error' => $e->getMessage()]);

} catch (Exception $e) {
    logMessage('ERROR: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Internal server error']);
}
