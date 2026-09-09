<?php

// ─── App Configuration ──────────────────────────────────────────────────────

// Set to true for additional debugging messages in the log file
define('DEBUG_MODE', false);
define('LOG_PATH',   __DIR__ . '/logs/live_events.log');

// Canvas JWKS endpoint — update with your institution's URL
// Found at: https://developerdocs.instructure.com/services/canvas/data-services/live-events/overview/file.data_service_setup
define('JWKS_URL', '<get_value_from_above_url');
define('ALLOWED_ALGORITHM', 'RS256');

// cURL timeout (seconds) when fetching JWKS
define('JWKS_FETCH_TIMEOUT', 10);

// Local cache file for JWKS keys (avoids fetching on every request)
define('JWKS_CACHE_PATH', __DIR__ . '/cache/jwks.json');
define('JWKS_CACHE_TTL',  3600);   // Re-fetch keys after 1 hour

// Optional: restrict accepted Canvas issuers (set to [] to skip check)
define('ALLOWED_ISSUERS', [
    'https://canvas.instructure.com',
	'https://live-events.canvas.instructure.com',
    'https://your.instructure.com',  // ← update with your Canvas URL
]);

// Canvas Developer Key and OAuth details
define('CANVAS_URL', 'https://your.instructure.com'); // ← update with your Canvas URL
define('CLIENT_ID', 'YOUR_CLIENT_ID'); // ← update with your Client ID; see instructions in auth.php
define('CLIENT_SECRET', 'YOUR_CLIENT_SECRET'); // ← update with your Client Secret; see instructions in auth.php
define('REDIRECT_URI', '<YOUR_URI_PATH>/auth.php');  // ← update with the URI to your host (not your Canvas path)

// ─── Handlers Configuration ─────────────────────────────────────────────────
/* Handlers are classes that extend handlers/LiveEventsHandler.php and should be
 * created in the handlers folder. If a handler requires its own configuration, that
 * should be put into the handlers/conf folder.
 *
 * Handlers using the Canvas API will require scopes (do not use unscoped developer keys).
 * The scopes should be added here. After adding a scope/scopes, you will need to make
 * sure the corresponding scope is added to the developer key in Canvas. You will also
 * need to re-authorize the token using the auth.php script. This re-authorization should
 * happen before you add the handler to EVENT_HANDLERS.
/*

/* Handler mappings
 * EVENT_HANDLERS is an associative array.
 * The key should be the event name received from Canvas.
 * The value should be a string or an array of strings representing handler classes.
 * The script looks for (and requires) a file corresponding to the string in the
 * handlers folder with .php extension. It then tries to insantiate an object of that
 * class.
 *
 * In the example, if the script receives a content_migration_completed event,
 * it looks for ./handlers/exampleHandler.php and creates a new exampleHander().
*/
define('EVENT_HANDLERS', [
	"content_migration_completed" => ["exampleHandler"]
]);
define('SCOPES', [
	"url:GET|/api/v1/courses/:course_id/external_tools"
]);

?>