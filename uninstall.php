<?php
/**
 * Uninstall Hook.
 *
 * @package SimpleShib
 * @since 1.2.0
 */

if ( ! defined( 'ABSPATH' ) || ! defined( 'WP_UNINSTALL_PLUGIN ' ) ) {
	die( 'ERROR: Direct access not permitted.' );
}

// Delete the options.
delete_site_option( 'simpleshib_options' );
