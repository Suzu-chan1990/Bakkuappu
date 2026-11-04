<?php
namespace YahnisElsts\PluginUpdateChecker\v5p6\Vcs;


if ( ! defined( 'ABSPATH' ) ) exit; // No direct access
if ( !interface_exists(BaseChecker::class, false) ):

	interface BaseChecker {
		/**
		 * Set the repository branch to use for updates. Defaults to 'master'.
		 *
		 * @param string $branch
		 * @return $this
		 */
		public function setBranch($branch);

		/**
		 * Set authentication credentials.
		 *
		 * @param array|string $credentials
		 * @return $this
		 */
		public function setAuthentication($credentials);

		/**
		 * @return Api
		 */
		public function getVcsApi();
	}

endif;
