<?php
/**
 * Copyright (C) 2026 Kyle Tuck
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This class provides the oauth services for the Canvas PHP Live Events Processor.
 *
 * It saves the token to a local file (using file locking). The tokenFileOperation function
 * can be rewritten to store the token in a database. Note that your web server must be
 * configured to block requests directly to the oauth_token.json file in this directory.
 * Create the file manually with garbage data first to make sure someone cannot simply
 * retrieve the file.
 */

require_once('config.php');
require_once('lib.php');

class OAuthService
{
    public function getAuthorizationUrl(): string
    {
		$scopes = implode(" ", SCOPES);
        $params = [
            'client_id'     => CLIENT_ID,
            'response_type' => 'code',
            'redirect_uri'  => REDIRECT_URI,
			'scope' => $scopes
        ];

        return CANVAS_URL .
            '/login/oauth2/auth?' .
            http_build_query($params);
    }

	public function getToken($code = null): string
	{
		if ($code) return $this->exchangeCodeForToken($code);
		else return $this->tokenFileOperation();
	}
	
	public function saveToken(array $tokenData): string
	{
		return $this->tokenFileOperation($tokenData);
	}

    private function exchangeCodeForToken(string $code): ?string
    {
		return $this->saveToken($this->postToken([
            'grant_type'    => 'authorization_code',
            'client_id'     => CLIENT_ID,
            'client_secret' => CLIENT_SECRET,
            'redirect_uri'  => REDIRECT_URI,
            'code'          => $code
        ]));
    }

	private function tokenFileOperation($tokenData = null)
	{
		$filePath = __DIR__ . '/oauth_token.json';
		$currentTime = time();
		$refreshAt = $currentTime - 120;
   
		// Open the file for reading and writing
		// Using 'c+' creates the file if it doesn't exist without truncating it
		$fileToken = fopen($filePath, 'c+');
		if (!$fileToken) {
			throw new Exception("Cannot open token file.");
		}

		// Acquire an exclusive lock (blocks until available)
		flock($fileToken, LOCK_EX);

		try {
			// Read current contents
			$fileSize = filesize($filePath);
			$content = $fileSize > 0 ? fread($fileToken, $fileSize) : '';
			$fileTokenData = json_decode($content, true);

			// If a token was provided as an argument, convert expires_in to expires_at
			if ($tokenData) {
				if (isset($tokenData['expires_in']))
					$tokenData['expires_at'] = (int)$currentTime + (int)$tokenData['expires_in'];
				// Check if the token file had valid data and if its token is newer than the provided one
				if ($fileTokenData && isset($fileTokenData['expires_at']) && isset($tokenData['expires_at']) && $fileTokenData['expires_at'] > $tokenData['expires_at']) {
					if ($fileTokenData['expires_at'] > $refreshAt)
						return $fileTokenData['access_token'];
					else
						$tokenData = $fileTokenData;
				}
			} else
				$tokenData = $fileTokenData;
			
			// check if the token needs to be refreshed
			if ($tokenData && $tokenData['expires_at'] < $refreshAt) {
				logMessage("Token expiring: " . $tokenData['expires_at'], DEBUG_MODE);
				$newTokenData = $this->refreshToken($tokenData['refresh_token']);
				$tokenData['expires_at'] = (int)$currentTime + (int)$newTokenData['expires_in'];
				$tokenData['access_token'] = $newTokenData['access_token'];
				logMessage("Refreshed token. New expiry: " . $tokenData['expires_at'], DEBUG_MODE);
			}
			
			// save the new token to the file
			if ($tokenData) {
				rewind($fileToken);          // Move pointer to the beginning
				ftruncate($fileToken, 0);     // Clear existing file content
				fwrite($fileToken, json_encode($tokenData));
				fflush($fileToken);          // Flush output before releasing lock				
			}

			return $tokenData['access_token'];
		} finally {
			// 6. Always release the lock and close the file handle
			flock($fileToken, LOCK_UN);
			fclose($fileToken);
		}
	}

    private function refreshToken(string $refreshToken): array
    {
        return $this->postToken([
            'grant_type'    => 'refresh_token',
            'client_id'     => CLIENT_ID,
            'client_secret' => CLIENT_SECRET,
            'refresh_token' => $refreshToken
        ]);
    }

    private function postToken(array $data): array
    {
        $ch = curl_init(
            CANVAS_URL .
            '/login/oauth2/token'
        );

        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($data)
        ]);

        $response = curl_exec($ch);

        if (!$response) {
            throw new Exception(curl_error($ch));
        }

        return json_decode($response, true);
    }
}
?>
