<?php
/**
 * SimpleShib: Simple_Shib class
 *
 * The Simple_Shib class is comprised of methods to support Single Sign-On via Shibboleth.
 *
 * @link https://wordpress.org/plugins/simpleshib/
 *
 * @package SimpleShib
 * @since 1.0.0
 */

/**
 * Simple_Shib class
 *
 * The Simple_Shib class is comprised of methods to support Single Sign-On via Shibboleth.
 *
 * @since 1.0.0
 */
class Simple_Shib {
	/**
	 * Debugging. Set to true to print debugging messages to the PHP error log.
	 *
	 * @since 1.0.0
	 * @var bool $debug
	 */
	private $debug = false;

	/**
	 * Disable authentication. Set to true to disable ALL login functionality, both WordPress native and Shib.
	 *
	 * @since 1.0.0
	 * @var bool $logins_disabled
	 */
	private $logins_disabled = false;

	/**
	 * Automatic account provisioning. When enabled, anyone with valid credentials at
	 * the IdP can login to WordPress. If they do not have a local WordPress account, one
	 * will be created for them. When the setting is disabled, the login process will fail
	 * if the user does not have a matching local WordPress account.
	 *
	 * @since 1.1.0
	 * @var bool $auto_account_provision
	 */
	private $auto_account_provision = true;

	/**
	 * Session initiator URL. The URL to initiate the session at the IdP. The user will be
	 * redirected here upon login. This should typically be "/Shibboleth.sso/Login" to ensure
	 * the SP on your server handles the request.
	 *
	 * @since 1.0.0
	 * @var string $session_initiator_url
	 */
	private $session_initiator_url = '/Shibboleth.sso/Login';

	/**
	 * Session logout URL. The user will be redirected here after being logged out of
	 * WordPress. It should typically be "/Shibboleth.sso/Logout" to ensure the SP on
	 * your server handles the request. There is an optional "return" parameter that
	 * can be used to redirect to a custom/central logout page.
	 * E.g.: '/Shibboleth.sso/Logout?return=https://idp.example.com/idp/profile/Logout'
	 *
	 * @since 1.0.0
	 * @var string $session_logout_url
	 */
	private $session_logout_url = '/Shibboleth.sso/Logout';

	/**
	 * Password change URL. The "change password" link in WordPress will point to this URL.
	 * Set to an empty string to disable/hide the link entirely.
	 *
	 * @since 1.0.0
	 * @var string $pass_change_url
	 */
	private $pass_change_url = 'http://example.com/accounts';

	/**
	 * Lost password URL. Password reset requests will point to this URL.
	 * This is required and cannot be an empty string.
	 *
	 * @since 1.0.0
	 * @var string $lost_pass_url
	 */
	private $lost_pass_url = 'http://example.com/accounts';

	/**
	 * Construct method.
	 *
	 * The construct of this class adds the Shibboleth authentication handler
	 * function to the WordPress authentication hook, hides the password fields,
	 * and tweaks a few things on the user profile page.
	 *
	 * @since 1.0.0
	 */
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

		// Bypass the logout confirmation and redirect to $session_logout_url defined above.
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


	/**
	 * Lost password.
	 *
	 * This method redirects the user to the URL defined in the settings above.
	 * It is hooked on 'login_form_lostpassword'.
	 *
	 * @since 1.0.0
	 *
	 * @see __construct()
	 * @see wp_redirect()
	 */
	public function lost_password() {
		// wp_safe_redirect() is not used here because $lost_pass_url is set
		// above (not provided by the user) and is likely an external URL.
		// Disable the phpcs sniff to avoid a warning.
		// phpcs:disable WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		wp_redirect( $this->lost_pass_url );
		// phpcs:enable
		exit();
	}


	/**
	 * Authenticate or Redirect
	 *
	 * This method handles user authentication. It either returns an error object,
	 * a user object, or redirects the user to the homepage or SSO initiator URL.
	 * It is hooked on 'authenticate'.
	 *
	 * @since 1.0.0
	 *
	 * @see __construct()
	 * {@see 'authenticate'}
	 * @see is_user_logged_in()
	 * @see is_shib_session_active()
	 * @see login_to_wordpress()
	 * @see wp_safe_redirect()
	 * @see get_initiator_url()
	 *
	 * @param WP_User $user WP_User if the user is authenticated. WP_Error or null otherwise.
	 * @param string  $username Username or email address.
	 * @param string  $password User password.
	 * @return WP_User Returns WP_User for successful authentication, otherwise WP_Error.
	 */
	public function authenticate_or_redirect( $user, $username, $password ) {
		if ( true === $this->logins_disabled ) {
			$error_obj = new WP_Error( 'shib', 'All logins are currently disabled.' );
			return $error_obj;
		}

		// Logged in at IdP and WP. Redirect to /.
		// TODO: Add a setting for a custom redirect path?
		if ( true === is_user_logged_in() && true === $this->is_shib_session_active() ) {
			if ( $this->debug ) {
				// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Shibboleth Debug: Logged in at WP and IdP. Redirecting to /.' );
				// phpcs:enable
			}

			wp_safe_redirect( '/' );
			exit();
		}

		// Logged in at IdP but not WP. Login to WP.
		if ( false === is_user_logged_in() && true === $this->is_shib_session_active() ) {
			if ( $this->debug ) {
				// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Shibboleth Debug: Logged in at IdP but not WP.' );
				// phpcs:enable
			}

			$login_obj = $this->login_to_wordpress();
			return $login_obj;
		}

		// Logged in nowhere. Redirect to IdP login page.
		if ( $this->debug ) {
			// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( 'Shibboleth Debug: Logged in nowhere!' );
			// phpcs:enable
		}

		// The redirect_to parameter is rawurlencode()ed in get_initiator_url().
		// phpcs:disable WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( isset( $_GET['redirect_to'] ) ) {
			wp_safe_redirect( $this->get_initiator_url( $_GET['redirect_to'] ) );
			// phpcs:enable
		} else {
			wp_safe_redirect( $this->get_initiator_url() );
		}

		exit();

		// The case of 'logged in at WP but not IdP' is handled in 'init' via
		// validate_shib_session().
	}


	/**
	 * Validate Shibboleth IdP session.
	 *
	 * This method determines if a Shibboleth session is active at the IdP by checking
	 * for the shibboleth HTTP headers. These headers cannot be forged because they are
	 * generated locally by shibd via Apache's mod_shib. For example, if the user attempts
	 * to spoof the "mail" header, it shows up as HTTP_MAIL instead of "mail".
	 *
	 * @since 1.0.0
	 *
	 * @return bool True if the IdP session is active, otherwise false.
	 */
	private function is_shib_session_active() {
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


	/**
	 * Generate the SSO initiator URL.
	 *
	 * This function generates the initiator URL for the Shibboleth session.
	 * In the case of multisite, the site that the user is logging in one is
	 * added as a return_to parameter to ensure they return to the same site.
	 *
	 * @since 1.0.0
	 *
	 * @see get_site_url()
	 * @see get_current_blog_id()
	 *
	 * @param string $redirect_to Optional. URL parameter from client. Null.
	 * @return string Full URL for SSO initialization.
	 */
	private function get_initiator_url( $redirect_to = null ) {
		// Get the login page URL.
		$return_to = get_site_url( get_current_blog_id(), 'wp-login.php', 'login' );

		if ( ! empty( $redirect_to ) ) {
			// Don't rawurlencode($RedirectTo) - we do this below.
			$return_to = add_query_arg( 'redirect_to', $redirect_to, $return_to );
		}

		$initiator_url = $this->session_initiator_url . '?target=' . rawurlencode( $return_to );

		return $initiator_url;
	}


	/**
	 * Log a user into WordPress.
	 *
	 * If $auto_account_provision is enabled, a WordPress account will be created if one
	 * does not exist. User data, including username, name, and email, are updated with
	 * values from the IdP during every user login.
	 *
	 * @since 1.0.0
	 *
	 * @see authenticate_or_redirect()
	 * @see get_user_by()
	 * @see wp_insert_user()
	 *
	 * @return WP_User Returns WP_User for successful authentication, otherwise WP_Error.
	 */
	private function login_to_wordpress() {
		// The headers have been confirmed to be !empty() in is_shib_session_active() above.
		// The data is coming from the IdP, not the user, so it is trustworthy.
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotValidated,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$shib['username']  = $_SERVER['uid'];
		$shib['firstName'] = $_SERVER['givenName'];
		$shib['lastName']  = $_SERVER['sn'];
		$shib['email']     = $_SERVER['mail'];
		// phpcs:enable

		// Check to see if they exist locally.
		$user_obj = get_user_by( 'login', $shib['username'] );
		if ( false === $user_obj && false === $this->auto_account_provision ) {
			do_action( 'wp_login_failed', $shib['username'] ); // Fire any login-failed hooks.
			$error_obj = new WP_Error(
				'shib',
				'<strong>Access Denied.</strong> Your login credentials are correct, but you do not have authorization to access this site.'
			);
			return $error_obj;
		}

		// The user_pass is irrelevant since we removed all internal WP auth functions.
		// However, if SimpleShib is ever disabled, WP will revert back to using user_pass, so it has to be safe.
		$insert_user_data = array(
			'user_pass'     => sha1( microtime() ),
			'user_login'    => $shib['username'],
			'user_nicename' => $shib['username'],
			'user_email'    => $shib['email'],
			'display_name'  => $shib['firstName'] . ' ' . $shib['lastName'],
			'nickname'      => $shib['username'],
			'first_name'    => $shib['firstName'],
			'last_name'     => $shib['lastName'],
		);

		// If wp_insert_user() receives 'ID' in the array, it will update the
		// user data of an existing account instead of creating a new account.
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

			// TODO: Add setting for support ticket URL.
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


	/**
	 * User logout handler.
	 *
	 * This method bypasses the "Are you sure?" prompt when logging out.
	 * It redirects the user directly to the SSO logout URL.
	 * It is hooked on 'login_form_logout'.
	 *
	 * @since 1.0.0
	 *
	 * @see __construct().
	 * {@see 'login_form_logout'}
	 * @see wp_logout().
	 * @see wp_safe_redirect().
	 */
	public function shib_logout() {
		// TODO: Is this still needed to bypass the logout prompt?
		wp_logout();
		wp_safe_redirect( $this->session_logout_url );
		exit();
	}


	/**
	 * Validate the Shibboleth IdP session
	 *
	 * This method validates the Shibboleth login session at the IdP.
	 * If the IdP's session disappears while the user is logged into WordPress
	 * locally, this will log them out.
	 * It is hooked on 'init'.
	 *
	 * @since 1.0.0
	 *
	 * @see __construct()
	 * {@see 'init'}
	 * @see is_user_logged_in()
	 * @see is_shib_session_active()
	 * @see wp_logout()
	 * @see wp_safe_redirect()
	 */
	public function validate_shib_session() {
		if ( true === is_user_logged_in() && false === $this->is_shib_session_active() ) {
			if ( $this->debug ) {
				// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Shibboleth Debug: validate_shib_session(): Logged in at WP but not IdP. Logging out!' );
				// phpcs:enable
			}

			wp_logout();
			wp_safe_redirect( '/' );
			exit();
		}
	}


	/**
	 * Add hooks to the admin sections.
	 *
	 * This method adds several hooks that change the user profile edit page.
	 *
	 * @since 1.0.0
	 *
	 * @see __construct()
	 * {@see 'admin_init'}
	 * @see add_action()
	 * {@see 'show_user_profile'}
	 * {@see 'admin_footer-profile.php'}
	 * {@see 'admin_footer-user-edit.php'}
	 * {@see 'personal_options_update'}
	 */
	public function add_admin_hooks() {
		// 'show_user_profile' fires after the "About Yourself" section when a user is editing their own profile.
		if ( ! empty( $this->pass_change_url ) ) {
			add_action( 'show_user_profile', array( $this, 'add_password_change_link' ) );
		}

		// Run a hook to disable certain HTML form fields on when editing your own profile and for admins
		// editing other users' profiles.
		add_action( 'admin_footer-profile.php', array( $this, 'disable_profile_fields' ) );
		add_action( 'admin_footer-user-edit.php', array( $this, 'disable_profile_fields' ) );

		// Don't just mark the HTML form fields readonly, but handle the POST data as well.
		add_action( 'personal_options_update', array( $this, 'disable_profile_fields_post' ) );
	}


	/**
	 * Add password change link.
	 *
	 * This method adds a row to the bottom of the user profile page that contains
	 * a password reset link pointing to the URL defined in the settings.
	 *
	 * @since 1.0.0
	 *
	 * @see add_admin_hooks()
	 */
	public function add_password_change_link() {
		echo '<table class="form-table"><tr>' . "\n";
		echo '<th>Change Password</th>' . "\n";
		echo '<td><a href="' . esc_url( $this->pass_change_url ) . '">Change your password</a></td>' . "\n";
		echo '</tr></table>' . "\n";
	}


	/**
	 * Disable profile fields.
	 *
	 * This method adds jQuery in the footer that disables the HTML form fields for
	 * first name, last name, nickname, and email address.
	 *
	 * @since 1.0.0
	 *
	 * @see add_admin_hooks()
	 * @see disable_profile_fields_post()
	 */
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


	/**
	 * Disable profile fields POST data.
	 *
	 * This method disables the processing of POST data from the user profile form for
	 * first name, last name, nickname, and email address.
	 * This is necessary because a DOM editor can be used to re-enable the form fields manually.
	 *
	 * @since 1.0.0
	 *
	 * @see add_admin_hooks()
	 * @see disable_profile_fields()
	 */
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

		// TODO
		// In my testing, I found problems with 'pre_user_email' not blocking email changes.
		// Since user data is updated from Shib upon every login, it really isn't a big deal.
		// This may be a WP core bug.
		add_filter(
			'pre_user_email',
			function () {
				$user_obj = wp_get_current_user();
				return $user_obj->user_email;
			}
		);
	}


}
