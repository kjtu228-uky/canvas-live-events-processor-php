<?php
/**
 * Copyright (C) 2026 Kyle Tuck
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * LiveEventsHandler defines the handle method and provides some Canvas API call functionality.
 * Event handlers should extend this class.
 *
 * So far this class is only providing GET and DELETE API call support. POST should be added.
 */

require_once(__DIR__ . '/../OAuthService.php');

class LiveEventsHandler
{
	public function handle(array $claims): void
	{
		logMessage('Processing event ' . $claims['metadata']['event_name']);
	}

	/**
	 * Execute a Canvas API request (except GET because of pagination)
	 *
	 * @param string $method   HTTP method (POST, PUT, DELETE)
	 * @param string $endpoint Canvas API endpoint beginning with "/"
	 * @param array  $data     Request data
	 *
	 * @return mixed
	 */
	protected function canvasApiRequest(
		string $method,
		string $endpoint,
		array $data = []
	): mixed
	{
		$url = CANVAS_URL . $endpoint;

		$oauth = new OAuthService();

		$ch = curl_init($url);

		$options = [
			CURLOPT_RETURNTRANSFER => true,
			CURLOPT_HTTPHEADER => [
				'Authorization: Bearer ' . $oauth->getToken(),
				'User-Agent: UkyLiveEvents/1.0 (elearning@uky.edu)',
				'Accept: application/json',
			],
		];

		switch (strtoupper($method)) {
			case 'POST':
				$options[CURLOPT_POST] = true;
				$options[CURLOPT_POSTFIELDS] = http_build_query($data);
				$options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded';
				break;

			case 'PUT':
				$options[CURLOPT_CUSTOMREQUEST] = 'PUT';
				$options[CURLOPT_POSTFIELDS] = http_build_query($data);
				$options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded';
				break;

			case 'DELETE':
				$options[CURLOPT_CUSTOMREQUEST] = 'DELETE';

				if (!empty($data)) {
					$options[CURLOPT_POSTFIELDS] = http_build_query($data);
					$options[CURLOPT_HTTPHEADER][] = 'Content-Type: application/x-www-form-urlencoded';
				}
				break;
		}

		curl_setopt_array($ch, $options);

		$response = curl_exec($ch);
		$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		$curlError = curl_error($ch);

		curl_close($ch);

		if ($curlError) {
			error_log("Canvas {$method} cURL error on {$endpoint}: {$curlError}");
			return null;
		}

		if ($httpCode < 200 || $httpCode >= 300) {
			error_log("Canvas {$method} failed on {$endpoint}: HTTP {$httpCode} — {$response}");
			return null;
		}

		// DELETE often returns no content
		if ($response === '' || $response === false) {
			return true;
		}

		$decoded = json_decode($response, true);

		if (json_last_error() !== JSON_ERROR_NONE) {
			error_log("Canvas {$method} returned invalid JSON: {$response}");
			return null;
		}

		return $decoded;
	}

	protected function canvasApiGet(string $endpoint): ?array
	{
		$results = [];

		$url = CANVAS_URL . $endpoint;

		while ($url) {
			$responseHeaders = [];

			$ch = curl_init($url);
			$oauth = new OAuthService();

			curl_setopt_array($ch, [
				CURLOPT_RETURNTRANSFER => true,
				CURLOPT_HTTPHEADER => [
					'Authorization: Bearer ' . $oauth->getToken(),
					'User-Agent: UkyLiveEvents/1.0 (elearning@uky.edu)',
					'Accept: application/json',
				],
				CURLOPT_HEADERFUNCTION => function ($curl, $header) use (&$responseHeaders) {
					$len = strlen($header);

					$parts = explode(':', $header, 2);
					if (count($parts) === 2) {
						$responseHeaders[strtolower(trim($parts[0]))][] = trim($parts[1]);
					}

					return $len;
				},
			]);

			$response = curl_exec($ch);
			$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);

			curl_close($ch);

			if ($httpCode !== 200 || $response === false) {
				error_log("Canvas API error: HTTP {$httpCode}\n  {$response}");
				return null;
			}

			$pageData = json_decode($response, true);

			if ($pageData === null) {
				error_log("Canvas API returned invalid JSON");
				return null;
			}

			// Most Canvas collection endpoints return arrays
			if (is_array($pageData) && array_is_list($pageData)) {
				$results = array_merge($results, $pageData);
			} else {
				// Non-paginated/object responses
				return $pageData;
			}

			// Find rel="next"
			$url = null;

			if (!empty($responseHeaders['link'])) {
				foreach ($responseHeaders['link'] as $linkHeader) {
					preg_match_all(
						'/<([^>]+)>;\s*rel="([^"]+)"/',
						$linkHeader,
						$matches,
						PREG_SET_ORDER
					);

					foreach ($matches as $match) {
						if ($match[2] === 'next') {
							$url = $match[1];
							break 2;
						}
					}
				}
			}
		}

		return $results;
	}

	protected function canvasApiPost(string $endpoint, array $data = []): ?array
	{
		$result = $this->canvasApiRequest('POST', $endpoint, $data);

		return is_array($result) ? $result : null;
	}

	protected function canvasApiPut(string $endpoint, array $data = []): ?array
	{
		$result = $this->canvasApiRequest('PUT', $endpoint, $data);

		return is_array($result) ? $result : null;
	}

	protected function canvasApiDelete(string $endpoint): bool
	{
		return $this->canvasApiRequest('DELETE', $endpoint) !== null;
	}

}

?>
