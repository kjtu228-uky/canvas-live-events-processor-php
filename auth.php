<?php
/**
 * Copyright (C) 2026 Kyle Tuck
 * SPDX-License-Identifier: GPL-3.0-or-later
 * 
 * OAuth target URI authentication page
 *
 * Canvas Admin Setup:
 *   Settings > Developer Keys
 *   Add an API key with the full URI path to this auth.php script as the Redirect URI.
 *   Scopes should be enforced and limited to the endpoints required for the app to function.
 *   Note that if additional Handlers are added, the scopes may need to change. That will require a
 *   complete reauth process.
 *
 *   Once the key is created, copy the client ID and secret to the config.php file (CLIENT_ID and CLIENT_SECRET).
 *   Do not forget to enable the key once it is created.
 *
 *   This script has been kept as simple as possible to provide the minimum necessary functionality.
 *   Feel free to make the success/fail section more complete.
 */

require_once('config.php');
require_once('OAuthService.php');

$oauth = new OAuthService();

if(isset($_GET['code'])) {
	$token = $oauth->getToken(
		$_GET['code']
	);
	$param = $token ? "?success=1" : "?success=0";
	header(
		'Location: ' . strtok($_SERVER['REQUEST_URI'], '?') . $param
	);
} else if (isset($_GET['success'])) {
	/* This is the only section that a page visitor should see (Success/Fail). */
	echo "Success: " . $_GET['success'];
} else {
	header(
		'Location: ' .
		$oauth->getAuthorizationUrl()
	);
	exit;	
}
exit;
?>
