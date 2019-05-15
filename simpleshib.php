<?php
/**
 * Plugin Name: SimpleShib
 * Plugin URI: https://wordpress.org/plugins/simpleshib/
 * Description: User authentication via Shibboleth Single Sign-On.
 * Version: 1.1.0
 * Author: Steve Guglielmo
 * License: MIT
 * Network: true
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
