<?php
/*
  This example Hander can be used to monitor content_migration_completed events from Canvas. It will 
*/
require_once(__DIR__ . '/LiveEventsHandler.php');

class exampleHandler extends LiveEventsHandler
{
	public function handle(array $claims): void
	{
		include(__DIR__ . '/conf/exampleHandlerConf.php');

		logMessage('exampleHandler: Handling event ' . $claims['metadata']['event_name'], DEBUG_MODE);
		if (isset($exampleHandlerMsg)) logMessage($exampleHandlerMsg);
		
		$courseId = $claims["body"]["context_id"];

		// get the list of external tools for the course
		$externalTools = $this->canvasApiGet(
			"/api/v1/courses/{$courseId}/external_tools?per_page=100"
		) ?? [];
		
		$logMsg = "";
		if (count($externalTools) > 0)
			$logMsg = 'Course ' . $courseId . ' has ' . count($externalTools) . ' tools:';
		
		foreach ($externalTools as $tool) {
			$logMsg .= "\n  " . $tool['name'];
		}
		if ($logMsg) logMessage($logMsg);
	}
}
