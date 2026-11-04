<?php

namespace YahnisElsts\PluginUpdateChecker\v5;


if ( ! defined( 'ABSPATH' ) ) exit; // No direct access
if ( !class_exists(PucFactory::class, false) ):

	class PucFactory extends \YahnisElsts\PluginUpdateChecker\v5p6\PucFactory {
	}

endif;
