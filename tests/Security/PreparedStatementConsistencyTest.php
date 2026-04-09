<?php
/*
 +-------------------------------------------------------------------------+
 | Copyright (C) 2004-2026 The Cacti Group                                 |
 +-------------------------------------------------------------------------+
 | Cacti: The Complete RRDtool-based Graphing Solution                     |
 +-------------------------------------------------------------------------+
*/

/*
 * Verify migrated files use prepared DB helpers exclusively.
 * Catches regressions where raw db_execute/db_fetch_* calls creep back in.
 */

describe('prepared statement consistency in webseer', function () {
	it('uses prepared DB helpers in all plugin files', function () {
		$targetFiles = array(
		'includes/functions.php',
		'poller_webseer.php',
		'remote.php',
		'setup.php',
		'webseer.php',
		'webseer_process.php',
		'webseer_proxies.php',
		'webseer_servers.php',
		);

		$rawPattern = '/\bdb_(?:execute|fetch_row|fetch_assoc|fetch_cell)\s*\(/';
		$preparedPattern = '/\bdb_(?:execute|fetch_row|fetch_assoc|fetch_cell)_prepared\s*\(/';

		foreach ($targetFiles as $relativeFile) {
			$path = realpath(__DIR__ . '/../../' . $relativeFile);

			if ($path === false) {
				continue;
			}

			$contents = file_get_contents($path);

			if ($contents === false) {
				continue;
			}

			$lines = explode("\n", $contents);
			$rawCallsOutsideComments = 0;

			foreach ($lines as $line) {
				$trimmed = ltrim($line);

				if (strpos($trimmed, '//') === 0 || strpos($trimmed, '*') === 0 || strpos($trimmed, '#') === 0) {
					continue;
				}

				if (preg_match($rawPattern, $line) && !preg_match($preparedPattern, $line)) {
					$rawCallsOutsideComments++;
				}
			}

			expect($rawCallsOutsideComments)->toBe(0,
				"File {$relativeFile} contains raw (unprepared) DB calls"
			);
		}
	});
});
