<?php
/**
 * SimpleShib: Simple_Shib class
 *
 * The Simple_Shib class is comprised of methods to support Single Sign-On via Shibboleth.
 *
 * @link https://wordpress.org/plugins/simpleshib/
 *
 * @package SimpleShib
 * @since 1.0.3
 */

/**
 * Simple_Shib class
 *
 * The Simple_Shib class is comprised of methods to support Single Sign-On via Shibboleth.
 *
 * @since 1.0.3
 */
class Simple_Shib {
	//
	// SETTINGS.
	//

	// Set to true to print some debugging messages to the PHP error log.
	private $_debug = false;

	// Set to true to disable ALL login functionality, both WordPress native and Shib.
	private $_logins_disabled = false;

	// The URL to initiate the session at the IdP. This should be "/Shibboleth.sso/Login".
	// This is handled by the SP on your server. The user will be redirected here upon login.
	// This cannot have any GET params due to _get_initiator_url().
	private $_session_initiator_url = '/Shibboleth.sso/Login';

	// Logout URL. Handled by the SP on your server. This should be "/Shibboleth.sso/Logout"
	// and can have an optional "?return=$URL" to redirect to a custom logout page.
	// Eg: /Shibboleth.sso/Logout?return=/blog/2016/11/close-your-browser/
	private $_session_logout_url = '/Shibboleth.sso/Logout';

	// A URL for the 'Change Password' link for users.
	// Set to an empty string to disable this link.
	private $_pass_change_url = 'http://example.com/accounts';

	// "Lost Password" URL. Required. Can be the same as above.
	private $_lost_pass_url = 'http://example.com/accounts';

	//
	// END SETTINGS.
	//

	public function __construct() {
		// Remove all existing WordPress authentication methods.
		remove_all_filters( 'authenticate' );

		// Hide password fields on profile.php and user-edit.php.
		add_filter( 'show_password_fields', '__return_false' );

		// Do not allow password resets within WP.
		add_filter( 'allow_password_reset', '__return_false' );

		// Change the lost password URL.
		add_action( 'login_form_lostpassword', array( $this, 'lost_password' ) );

		// Add our Shib auth function to WordPress's authentication workflow.
		add_filter( 'authenticate', array( $this, 'authenticate_or_redirect' ), 10, 3 );

		// Bypass the logout confirmation and redirect to $_session_logout_url defined above.
		add_action( 'login_form_logout', array( $this, 'shib_logout' ) );

		// Check for IdP sessions that have disappeared.
		// The init hooks fire when WP is finished loading on every page, but before
		// headers are sent. We have to run validate_shib_session() in the init hook
		// instead of in the plugin construct because is_user_logged_in() only works
		// after WP is finished loading.
		add_action( 'init', array( $this, 'validate_shib_session' ) );

		// Add hooks related to the user profile page.
		add_action( 'admin_init', array( $this, 'add_admin_hooks' ) );
	}


	// Send the "lost password" link to the defined location.
	public function lost_password() {
		wp_redirect( $this->_lost_pass_url );
		exit();
	}


	// This function is run on the WordPress login page.
	// Returns a WP_Error or a WP_User object.
	public function authenticate_or_redirect( $user, $username, $password ) {
		if ( true === $this->_logins_disabled ) {
			$error_obj = new WP_Error( 'shib', 'All logins are currently disabled.' );
			return $error_obj;
		}

		// Logged in at IdP and WP. Redirect to /.
		// TODO: Add a setting for a custom redirect path?
		if ( true === is_user_logged_in() && true === $this->_is_shib_session_active() ) {
			if ( $this->_debug ) {
				error_log( 'Shibboleth Debug: auth_or_redirect(): Logged in at WP and IdP. Redirecting to /.' );
			}

			wp_safe_redirect( '/' );
			exit();
		}

		// Logged in at IdP but not WP. Login to WP.
		if ( false === is_user_logged_in() && true === $this->_is_shib_session_active() ) {
			if ( $this->_debug ) {
				error_log( 'Shibboleth Debug: auth_or_redirect(): Logged in at IdP but not WP.' );
			}

			$login_obj = $this->_login_to_wordpress();
			return $login_obj;
		}

		// Logged in nowhere. Redirect to IdP login page.
		if ( $this->_debug ) {
			error_log( 'Shibboleth Debug: auth_or_redirect(): Logged in nowhere!' );
		}

		if ( isset( $_GET['redirect_to'] ) ) {
			wp_safe_redirect( $this->_get_initiator_url( $_GET['redirect_to'] ) );
		} else {
			wp_safe_redirect( $this->_get_initiator_url() );
		}

		exit();

		// The case of 'logged in at WP but not IdP' is handled in 'init' via
		// validate_shib_session().
	}


	// Check if a Shibboleth session is active. This means the user has logged into the IdP successfully.
	// This checks for the shibboleth HTTP headers. These headers cannot be forged because they actually
	// are generated locally in shibd via Apache's mod_shib. If the user spoofs the "mail" header,
	// for example, it actually shows up as HTTP_MAIL instead of "mail".
	// Returns true or false.
	private function _is_shib_session_active() {
		if ( isset( $_SERVER['AUTH_TYPE'] ) && 'shibboleth' === $_SERVER['AUTH_TYPE']
			&& ! empty( $_SERVER['Shib-Session-ID'] )
			&& ! empty( $_SERVER['uid'] )
			&& ! empty( $_SERVER['givenName'] )
			&& ! empty( $_SERVER['sn'] )
			&& ! empty( $_SERVER['mail'] )
		) {
			return true;
		} else {
			return false;
		}
	}


	// Generate the URL to initiate Shibboleth login.
	// This takes in mind the site the user is logging in on
	// as well as the redirect_to GET value.
	private function _get_initiator_url( $redirect_to = null ) {
		// Get the login page URL.
		$return_to = get_site_url( get_current_blog_id(), 'wp-login.php', 'login' );

		if ( ! empty( $redirect_to ) ) {
			// Don't rawurlencode($RedirectTo) - we do this below.
			$return_to = add_query_arg( 'redirect_to', $redirect_to, $return_to );
		}

		$initiator_url = $this->_session_initiator_url . '?target=' . rawurlencode( $return_to );

		return $initiator_url;
	}


	// Log a user into WP locally. This is called from authenticate_or_redirect().
	// If this is the first time we've seen this user, a new WP account will be created.
	// Exiting users will have their data updated based on the Shib headers.
	private function _login_to_wordpress() {
		// The headers have been confirmed to be !empty() in _is_shib_session_active() above.
		// The data is coming from the IdP, not the user, so lets trust it.
		$shib['username']  = $_SERVER['uid'];
		$shib['firstName'] = $_SERVER['givenName'];
		$shib['lastName']  = $_SERVER['sn'];
		$shib['email']     = $_SERVER['mail'];

		// Check to see if they exist locally.
		$user_obj = get_user_by( 'login', $shib['username'] );

		// See https://developer.wordpress.org/reference/functions/wp_insert_user/.
		$insert_user_data = array(
				// user_pass is irrelevant since we removed all internal WP auth functions.
				// However, if this plugin is ever disabled/removed, WP will revert back to using user_pass, so it has to be safe.
				'user_pass'     => sha1( microtime() ),
				'user_login'    => $shib['username'],
				'user_nicename' => $shib['username'],
				'user_email'    => $shib['email'],
				'display_name'  => $shib['firstName'] . ' ' . $shib['lastName'],
				'nickname'      => $shib['username'],
				'first_name'    => $shib['firstName'],
				'last_name'     => $shib['lastName'],
		);

		// If wp_insert_user() receives 'ID' in the array, it will update the user data of an existing account
		// instead of creating a new account.
		// Also, return slightly different error messages below based on if we're updating an account or creating an account.
		// This is to aid debugging any issues/tickets that may occur.
		if ( false !== $user_obj && is_numeric( $user_obj->ID ) ) {
			$insert_user_data['ID'] = $user_obj->ID;
			$error_msg              = 'syncing';
		} else {
			$error_msg = 'creating';
		}

		$new_user = wp_insert_user( $insert_user_data );

		// wp_insert_user() returns either int of the userid or WP_Error object.
		if ( is_wp_error( $new_user ) || ! is_int( $new_user ) ) {
			do_action( 'wp_login_failed', $shib['username'] ); // Fire any login-failed hooks.

			// TODO: Setting for support ticket URL.
			$error_obj = new WP_Error(
				'shib',
				'<strong>ERROR:</strong> credentials are correct, but an error occurred ' . $error_msg . ' the local account. Please open a support ticket with this error.'
			);
			return $error_obj;
		} else {
			// Created the user successfully.
			$user_obj = new WP_User( $new_user );
			return $user_obj;
		}
	}


	// Bypass the "are you sure" prompt when logging out and
	// redirect to the Shibboleth logout URL.
	// TODO: Is this still needed?
	public function shib_logout() {
		wp_logout();
		wp_safe_redirect( $this->_session_logout_url );
		exit();
	}


	// If the Shib session disappears while the user is logged into WP, log them out.
	// Hooked on 'init'.
	public function validate_shib_session() {
		if ( true === is_user_logged_in() && false === $this->_is_shib_session_active() ) {
			if ( $this->_debug ) {
				error_log( 'Shibboleth Debug: validate_shib_session(): Logged in at WP but not IdP. Logging out!' );
			}

			wp_logout();
			wp_safe_redirect( '/' );
			exit();
		}
	}


	//
	// The functions below here are related to the user profile page.
	//

	// Various hooks for the admin/user profile screen. Hooked on 'admin_init'.
	public function add_admin_hooks() {
		// 'show_user_profile' fires after the "About Yourself" section when a user is editing their own profile.
		if ( ! empty( $this->_pass_change_url ) ) {
			add_action( 'show_user_profile', array( $this, 'add_password_change_link' ) );
		}

		// Run a hook to disable certain HTML form fields on when editing your own profile and for admins
		// editing other users' profiles.
		add_action( 'admin_footer-profile.php', array( $this, 'disable_profile_fields' ) );
		add_action( 'admin_footer-user-edit.php', array( $this, 'disable_profile_fields' ) );

		// Don't just mark the HTML form fields readonly, but handle the POST data as well.
		add_action( 'personal_options_update', array( $this, 'disable_profile_fields_post' ) );
	}


	// Add another row at the bottom of the users' profile page that includes a password reset link.
	public function add_password_change_link() {
		echo '<table class="form-table"><tr>' . "\n";
		echo '<th>Change Password</th>' . "\n";
		echo '<td><a href="' . esc_url( $this->_pass_change_url ) . '">Change your password</a></td>' . "\n";
		echo '</tr></table>' . "\n";
	}


	// Put some jquery in the footer that disables the html form fields for: first name, last name, nickname, and email.
	// NOTE: This just disables the forms, it doesn't handle the POST data. See disable_profile_fields_post() below.
	public function disable_profile_fields() {
		// Use readonly instead of disabled because disabled fields are not included in the POST data.
		echo '<script type="text/javascript">jQuery(function() {' . "\n";
			echo 'jQuery("#first_name,#last_name,#nickname,#email").prop("readonly", true);' . "\n";
			// Add a notice to users that they cannot change certain profile fields.
			echo 'jQuery("#first_name").parents(".form-table").before("<div class=\"updated\"><p>';
			echo 'Names and email addresses are centrally managed and cannot be changed from within WordPress.</p></div>");';
			echo "\n";
		echo '});</script>';
	}


	// Don't just disable the HTML form fields; also make sure we handle the processing of POST data as well.
	// Script kiddies can use a DOM editor to re-enable the form fields manually.
	public function disable_profile_fields_post() {
		add_filter(
			'pre_user_first_name',
			function () {
				$user_obj = wp_get_current_user();
				return $user_obj->first_name;
			}
		);

		add_filter(
			'pre_user_last_name',
			function () {
				$user_obj = wp_get_current_user();
				return $user_obj->last_name;
			}
		);

		add_filter(
			'pre_user_nickname',
			function () {
				$user_obj = wp_get_current_user();
				return $user_obj->user_nicename;
			}
		);

		// TODO: This doesn't work perfectly. In my testing, I found problems with 'pre_user_email' not blocking email changes.
		// Since user data is updated from Shib upon every login, it really isn't a big deal. This may be a WP bug.
		add_filter(
			'pre_user_email',
			function () {
				$user_obj = wp_get_current_user();
				return $user_obj->user_email;
			}
		);
	}


}
