<?php
/**
 * Plugin Name: SimpleShib
 * Plugin URI: https://github.com/srguglielmo/SimpleShib
 * Description: User authentication via Shibboleth Single Sign-On.
 * Version: 1.0.2
 * Author: Steve Guglielmo
 * License: MIT
 *
 * See the LICENSE file for more information.
 *
 * @package SimpleShib
 */

if ( ! defined( 'ABSPATH' ) ) {
	die( 'No script kiddies please!' );
}

require_once 'class-simple-shib.php';

new Simple_Shib();
