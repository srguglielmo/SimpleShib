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
	 * Array containing current options.
	 *
	 * @since 1.2.0
	 * @var array $options
	 */
	private $options;

	/**
	 * Array containing the default options.
	 *
	 * @since 1.2.0
	 * @var const array DEFAULT_OPTS
	 */
	private const DEFAULT_OPTS = array(
		'attr_email'         => 'mail',
		'attr_firstname'     => 'givenName',
		'attr_lastname'      => 'sn',
		'attr_username'      => 'uid',
		'autoprovision'      => false,
		'debug'              => false,
		'enabled'            => false,
		'pass_change_url'    => 'https://www.example.com/passchange',
		'pass_reset_url'     => 'https://www.example.com/passreset',
		'session_init_url'   => '/Shibboleth.sso/Login',
		'session_logout_url' => '/Shibboleth.sso/Logout',
	);


	/**
	 * Construct method.
	 *
	 * The construct of this class initializes options, adds the Shibboleth
	 * authentication handler, adds the settings page, and tweaks the user profile page.
	 *
	 * @since 1.0.0
	 *
	 * @see remove_all_filters()
	 * @see add_filter()
	 * @see add_action()
	 */
	public function __construct() {
		// Initialize plugin options.
		$this->initialize_options();

		// If SSO is _not_ enabled, this plugin still does a few things (e.g. adding the settings menu),
		// but it doesn't add the actual authenticate and session validation filters/actions.
		if ( true === $this->options['enabled'] ) {
			// Replace all existing WordPress authentication methods with our Shib auth handling.
			remove_all_filters( 'authenticate' );
			add_filter( 'authenticate', array( $this, 'authenticate_or_redirect' ), 1, 3 );

			// Check for IdP sessions that have disappeared.
			add_action( 'init', array( $this, 'validate_shib_session' ), 1, 0 );

			// Bypass the logout confirmation and redirect to $session_logout_url defined above.
			add_action( 'login_form_logout', array( $this, 'shib_logout' ), 5, 0 );
		}

		// Add the settings menu page and handle POST options.
		if ( ! is_multisite() ) {
			add_action( 'admin_menu', array( $this, 'add_settings_menu' ), 10, 0 );
			add_action( 'admin_post_simpleshib_settings', array( $this, 'handle_post' ), 5, 0 );
		} else {
			add_action( 'network_admin_menu', array( $this, 'add_settings_menu' ), 10, 0 );
			add_action( 'network_admin_edit_simpleshib_settings', array( $this, 'handle_post' ), 5, 0 );
		}

		// Hide password fields on profile.php and user-edit.php, and do not alow resets.
		add_action( 'admin_init', array( $this, 'admin_init' ) );
		add_filter( 'show_password_fields', '__return_false' );
		add_filter( 'allow_password_reset', '__return_false' );
		add_action( 'login_form_lostpassword', array( $this, 'lost_password' ) );
	}


	/**
	 * Initializes plugin options.
	 *
	 * This method will fetch the options from the database. If options do not
	 * exist, they will be added with appropriate default values. Note that
	 * FOO_site_option() functions are safe for both single-site and multi-site.
	 *
	 * @see get_site_option()
	 * @see add_site_option()
	 * @since 1.2.0
	 */
	private function initialize_options() {
		$options = get_site_option( 'simpleshib_options', false );
		if ( false === $options || empty( $options ) ) {
			// The options don't exist in the DB. Add them with default values.
			$options = self::DEFAULT_OPTS;
			add_site_option( 'simpleshib_options', $options );
		}

		$this->options = $options;
	}


	/**
	 * Sanitizes plugin options submitted via POST.
	 *
	 * Unknown keys will be unset. Invalid values will be replaced with defaults.
	 *
	 * @since 1.2.0
	 * @param mixed $given_opts Options submitted by the user.
	 * @return array Sanitized array of known options.
	 */
	public function sanitize_options( $given_opts ) {
		$defaults = self::DEFAULT_OPTS;

		if ( empty( $given_opts ) || ! is_array( $given_opts ) ) {
			return $defaults;
		}

		$clean_opts = array();
		foreach ( $given_opts as $key => $value ) {
			switch ( $key ) {
				// Strings (non-URL).
				case 'attr_email':
				case 'attr_firstname':
				case 'attr_lastname':
				case 'attr_username':
					if ( ctype_alnum( trim( $value ) ) ) {
						$clean_opts[ $key ] = (string) $value;
					}
					continue 2;

				// Booleans.
				case 'autoprovision':
				case 'debug':
				case 'enabled':
					$validated = filter_var( $value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE );
					if ( ! is_null( $validated ) ) {
						$clean_opts[ $key ] = (bool) $validated;
					}
					continue 2;

				// Full URL strings.
				case 'pass_change_url':
				case 'pass_reset_url':
					$sanitized = filter_var( $value, FILTER_SANITIZE_URL );
					$validated = filter_var( $sanitized, FILTER_VALIDATE_URL, array( FILTER_FLAG_SCHEME_REQUIRED, FILTER_FLAG_HOST_REQUIRED, FILTER_FLAG_PATH_REQUIRED ) );
					if ( false !== $sanitized && false !== $validated && ! empty( $validated ) ) {
						$clean_opts[ $key ] = (string) $validated;
					}
					continue 2;

				// Strings, but not full URLs (e.g. "/Shibboleth.sso/Login").
				case 'session_init_url':
				case 'session_logout_url':
					$sanitized = filter_var( $value, FILTER_SANITIZE_URL );
					if ( false !== $sanitized && ! empty( $sanitized ) ) {
						$clean_opts[ $key ] = (string) $sanitized;
					}
					continue 2;
			}
		}

		return $clean_opts;
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
	 * @see is_user_logged_in()
	 * @see is_shib_session_active()
	 * @see login_to_wordpress()
	 * @see wp_safe_redirect()
	 * @see get_initiator_url()
	 *
	 * @param WP_User $user WP_User if the user is authenticated. WP_Error or null otherwise.
	 * @param string  $username Username or email address.
	 * @param string  $password User password.
	 *
	 * @return WP_User Returns WP_User for successful authentication, otherwise WP_Error.
	 */
	public function authenticate_or_redirect( $user, $username, $password ) {
		// Logged in at IdP and WP. Redirect to /.
		if ( true === is_user_logged_in() && true === $this->is_shib_session_active() ) {
			$this->debug( 'Logged in at WP and IdP. Redirecting to /.' );
			wp_safe_redirect( get_site_url() );
			exit();
		}

		// Logged in at IdP but not WP. Login to WP.
		if ( false === is_user_logged_in() && true === $this->is_shib_session_active() ) {
			$this->debug( 'Logged in at IdP but not WP.' );
			$login_obj = $this->login_to_wordpress();
			return $login_obj;
		}

		// Logged in nowhere. Redirect to IdP login page.
		$this->debug( 'Logged in nowhere!' );

		// The redirect_to parameter is rawurlencode()ed in get_initiator_url().
		// phpcs:disable WordPress.Security.NonceVerification.Recommended,WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		if ( isset( $_GET['redirect_to'] ) ) {
			wp_safe_redirect( $this->get_initiator_url( $_GET['redirect_to'] ) );
			// phpcs:enable
		} else {
			wp_safe_redirect( $this->get_initiator_url() );
		}

		exit();

		// The case of 'logged in at WP but not IdP' is handled in 'init' via validate_shib_session().
	}


	/**
	 * Admin init.
	 *
	 * Apply several actions on the user profile edit pages.
	 *
	 * @since 1.0.0
	 *
	 * @see add_action()
	 */
	public function admin_init() {
		// 'show_user_profile' fires after the "About Yourself" section when a user is editing their own profile.
		add_action( 'show_user_profile', array( $this, 'add_password_change_link' ) );

		// Run a hook to disable certain HTML form fields on when editing your own profile and for admins
		// editing other users' profiles.
		add_action( 'admin_footer-profile.php', array( $this, 'disable_profile_fields' ) );
		add_action( 'admin_footer-user-edit.php', array( $this, 'disable_profile_fields' ) );

		// Don't just mark the HTML form fields readonly, but handle the POST data as well.
		add_action( 'personal_options_update', array( $this, 'disable_profile_fields_post' ) );
	}


	/**
	 * Adds a settings menu.
	 *
	 * Hooked on admin_menu and network_admin_menu.
	 *
	 * @since 1.2.0
	 * @see add_submenu_page()
	 */
	public function add_settings_menu() {
		if ( ! is_multisite() ) {
			$parent_slug = 'options-general.php'; // Single site admin page.
		} else {
			$parent_slug = 'settings.php'; // Network admin page.
		}

		add_submenu_page(
			$parent_slug,
			'SimpleShib Settings',
			'SimpleShib',
			'manage_options',
			'simpleshib_settings',
			array( $this, 'settings_menu_html' ),
			null
		);
	}


	/**
	 * Prints the HTML for the settings page.
	 *
	 * @since 1.2.0
	 */
	public function settings_menu_html() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return;
		}

		echo '<div class="wrap">' . "\n";
		echo "<h1>SimpleShib Settings</h1>\n";

		// Determine the POST action URL.
		if ( ! is_multisite() ) {
			$post_url = add_query_arg( 'action', 'simpleshib_settings', admin_url( 'admin-post.php' ) );
		} else {
			$post_url = add_query_arg( 'action', 'simpleshib_settings', network_admin_url( 'edit.php' ) );
		}

		?>
		<form method="post" action="<?php echo esc_url( $post_url ); ?>">
		<?php wp_nonce_field( 'simpleshib-opts-nonce', 'simpleshib-opts-nonce' ); ?>
		<table class="form-table" role="presentation">
		<tr>
			<th scope="row">Enable SSO</th>
			<td><label for="simpleshib_options-enabled">
			<input type="checkbox" name="simpleshib_options-enabled" id="simpleshib_options-enabled" value="1"<?php echo ( true === $this->options['enabled'] ? ' checked' : '' ); ?> />
			Enable and enforce SSO. Local account passwords will no longer be used.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Email Attribute</th>
			<td><label for="simpleshib_options-attr_email">
			<input type="text" size="40" required name="simpleshib_options-attr_email" id="simpleshib_options-attr_email" value="<?php echo esc_attr( $this->options['attr_email'] ); ?>" /><br>
			The SAML attribute released by the IdP containing the person's email address. Defaults to <code>mail</code>.
			</label></td>
		</tr>
		<tr>
			<th scope="row">First Name Attribute</th>
			<td><label for="simpleshib_options-attr_firstname">
			<input type="text" size="40" required name="simpleshib_options-attr_firstname" id="simpleshib_options-attr_firstname" value="<?php echo esc_attr( $this->options['attr_firstname'] ); ?>" /><br>
			The SAML attribute released by the IdP containing the person's (preferred) first name. Defaults to <code>givenName</code>.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Last Name Attribute</th>
			<td><label for="simpleshib_options-attr_lastname">
			<input type="text" size="40" required name="simpleshib_options-attr_lastname" id="simpleshib_options-attr_lastname" value="<?php echo esc_attr( $this->options['attr_lastname'] ); ?>" /><br>
			The SAML attribute released by the IdP containing the person's (preferred) last name. Defaults to <code>sn</code>.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Username Attribute</th>
			<td><label for="simpleshib_options-attr_username">
			<input type="text" size="40" required name="simpleshib_options-attr_username" id="simpleshib_options-attr_username" value="<?php echo esc_attr( $this->options['attr_username'] ); ?>" /><br>
			The SAML attribute released by the IdP containing the person's local WordPress username. Defaults to <code>uid</code>.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Autoprovision Accounts</th>
			<td><label for="simpleshib_options-autoprovision">
			<input type="checkbox" name="simpleshib_options-autoprovision" id="simpleshib_options-autoprovision" value="1"<?php echo ( true === $this->options['autoprovision'] ? ' checked' : '' ); ?> />
			If enabled, local accounts will <em>automatically</em> be created (as needed) after authenticating at the IdP. If disabled, only users with pre-existing local accounts can login.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Session Initiation URL</th>
			<td><label for="simpleshib_options-session_init_url">
			<input type="text" name="simpleshib_options-session_init_url" id="simpleshib_options-session_init_url" required size="70" value="<?php echo esc_attr( $this->options['session_init_url'] ); ?>" /><br>
			This generally should not be changed. Defaults to <code>/Shibboleth.sso/Login</code>.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Session Logout URL</th>
			<td><label for="simpleshib_options-session_logout_url">
			<input type="text" name="simpleshib_options-session_logout_url" id="simpleshib_options-session_logout_url" required size="70" value="<?php echo esc_attr( $this->options['session_logout_url'] ); ?>" /><br>
			This generally should not be changed, but an optional return URL can be provided.<br>
			E.g. <code>/Shibboleth.sso/Logout?return=https://idp.example.com/idp/profile/Logout</code>.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Password Change URL</th>
			<td><label for="simpleshib_options-pass_change_url">
			<input type="text" name="simpleshib_options-pass_change_url" id="simpleshib_options-pass_change_url" required size="70" value="<?php echo esc_attr( $this->options['pass_change_url'] ); ?>" /><br>
			Full URL where users can change their SSO password.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Password Reset URL</th>
			<td><label for="simpleshib_options-pass_reset_url">
			<input type="text" name="simpleshib_options-pass_reset_url" id="simpleshib_options-pass_reset_url" required size="70" value="<?php echo esc_attr( $this->options['pass_reset_url'] ); ?>" /><br>
			Full URL where users can reset their forgotten/lost SSO password.
			</label></td>
		</tr>
		<tr>
			<th scope="row">Debug</th>
			<td><label for="simpleshib_options-debug">
			<input type="checkbox" name="simpleshib_options-debug" id="simpleshib_options-debug" value="1"<?php echo ( true === $this->options['debug'] ? ' checked' : '' ); ?> />
			Debugging messages will be logged to PHP's error log.
			</label></td>
		</tr>
		</table>
		<?php
		submit_button();
		echo "\n";
		echo "</form>\n";
		echo "</div>\n";
	}


	/**
	 * Handle POST from settings form.
	 *
	 * Hooked on admin_post_simpleshib_settings.
	 *
	 * @since 1.2.0
	 * @see 'admin_post_$action'
	 * @see wp_verify_nonce()
	 * @see update_site_option()
	 */
	public function handle_post() {
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== $_SERVER['REQUEST_METHOD'] || empty( $_POST ) ) {
			echo "Request method isn't POST or post data is empty!\n";
			die;
		}

		// Verify the security nonce value.
		if ( empty( $_POST['simpleshib-opts-nonce'] ) ) {
			echo "Missing nonce!\n";
			die;
		}
		$nonce = wp_verify_nonce( $_POST['simpleshib-opts-nonce'], 'simpleshib-opts-nonce' ); // phpcs:ignore
		if ( 1 !== $nonce ) {
			echo "Nonce is bad!\n";
			die;
		}

		$new_options = array();
		foreach ( self::DEFAULT_OPTS as $key => $value ) {
			if ( empty( $_POST[ 'simpleshib_options-' . $key ] ) ) {
				// Unchecked checkboxes are empty() in the POST data.
				$_POST[ 'simpleshib_options-' . $key ] = false;
			}

			$new_options[ $key ] = $_POST[ 'simpleshib_options-' . $key ];  // phpcs:ignore
		}

		$clean_options = $this->sanitize_options( $new_options );
		update_site_option( 'simpleshib_options', $clean_options );

		// Generate the return_to URL.
		if ( ! is_multisite() ) {
			$return_to_page = 'options-general.php';
		} else {
			$return_to_page = 'settings.php';
		}
		$return_to = add_query_arg(
			array(
				'updated' => 'true',
				'page'    => 'simpleshib_settings',
			),
			network_admin_url( $return_to_page )
		);

		wp_safe_redirect( $return_to );
		die;
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
	 * @since 1.2.1 Added support for custom attributes.
	 * @return bool True if the IdP session is active, otherwise false.
	 */
	private function is_shib_session_active() {
		if ( isset( $_SERVER['AUTH_TYPE'] ) && 'shibboleth' === $_SERVER['AUTH_TYPE']
			&& ! empty( $_SERVER['Shib-Session-ID'] )
			&& ! empty( $_SERVER[ $this->options['attr_email'] ] )
			&& ! empty( $_SERVER[ $this->options['attr_firstname'] ] )
			&& ! empty( $_SERVER[ $this->options['attr_lastname'] ] )
			&& ! empty( $_SERVER[ $this->options['attr_username'] ] )
		) {
			return true;
		} else {
			return false;
		}
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
	 * @see is_user_logged_in()
	 * @see is_shib_session_active()
	 * @see wp_logout()
	 * @see wp_safe_redirect()
	 */
	public function validate_shib_session() {
		if ( true === is_user_logged_in() && false === $this->is_shib_session_active() ) {
			$this->debug( 'validate_shib_session(): Logged in at WP but not IdP. Logging out!' );
			wp_logout();
			wp_safe_redirect( get_site_url() );
			die;
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
	 *
	 * @return string Full URL for SSO initialization.
	 */
	private function get_initiator_url( $redirect_to = null ) {
		// Get the login page URL.
		$return_to = get_site_url( get_current_blog_id(), 'wp-login.php', 'login' );

		if ( ! empty( $redirect_to ) ) {
			// Don't rawurlencode($RedirectTo) - we do this below.
			$return_to = add_query_arg( 'redirect_to', $redirect_to, $return_to );
		}

		$initiator_url = $this->options['session_init_url'] . '?target=' . rawurlencode( $return_to );

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
		$shib['email']     = $_SERVER[ $this->options['attr_email'] ];
		$shib['firstName'] = $_SERVER[ $this->options['attr_firstname'] ];
		$shib['lastName']  = $_SERVER[ $this->options['attr_lastname'] ];
		$shib['username']  = $_SERVER[ $this->options['attr_username'] ];
		// phpcs:enable

		// Check to see if they exist locally.
		$user_obj = get_user_by( 'login', $shib['username'] );
		if ( false === $user_obj && false === $this->options['autoprovision'] ) {
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
	 * @see wp_logout().
	 * @see wp_safe_redirect().
	 */
	public function shib_logout() {
		// TODO: Is this still needed to bypass the logout prompt?
		wp_logout();
		wp_safe_redirect( $this->options['session_logout_url'] );
		exit();
	}


	/**
	 * Lost password.
	 *
	 * This method redirects the user to the URL defined in the settings above.
	 * It is hooked on 'login_form_lostpassword'.
	 *
	 * @since 1.0.0
	 *
	 * @see wp_redirect()
	 */
	public function lost_password() {
		// wp_safe_redirect() is not used here because $lost_pass_url is set
		// in the plugin configuration (not provided by the user) and is likely
		// an external URL. The phpcs sniff is disabled to avoid a warning.
		// phpcs:disable WordPress.Security.SafeRedirect.wp_redirect_wp_redirect
		wp_redirect( $this->options['pass_reset_url'] );
		// phpcs:enable
		exit();
	}


	/**
	 * Add password change link.
	 *
	 * This method adds a row to the bottom of the user profile page that contains
	 * a password reset link pointing to the URL defined in the settings.
	 *
	 * @since 1.0.0
	 */
	public function add_password_change_link() {
		echo '<table class="form-table"><tr>' . "\n";
		echo '<th>Change Password</th>' . "\n";
		echo '<td><a href="' . esc_url( $this->options['pass_change_url'] ) . '">Change your password</a></td>' . "\n";
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
	 * first name, last name, nickname, and email address. This is necessary because a
	 * DOM editor can be used to re-enable the form fields manually.
	 *
	 * @since 1.0.0
	 *
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


	/**
	 * Logs debugging messages to PHP's error log.
	 *
	 * @since 1.2.0
	 * @param string $msg Debugging message.
	 */
	private function debug( $msg ) {
		if ( true === $this->options['debug'] && ! empty( $msg ) ) {
			// phpcs:disable WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( 'SimpleShib-Debug: ' . $msg );
			// phpcs:enable
		}
	}


}
