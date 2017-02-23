<?php
/*
Plugin Name: SimpleShib
Plugin URI: https://github.com/srguglielmo/SimpleShib
Description: Authenticate users through Shibboleth Single Sign-On.
Version: 1.0.1
Author: Stephen R Guglielmo
Author URI: https://guglielmo.us/
License: MIT
Please see the LICENSE file for more information.
*/

defined('ABSPATH') or die('No script kiddies please!');

new SimpleShib();

class SimpleShib {

	//
	// SETTINGS
	//

	// Set to true to print some debugging messages to the PHP error log.
	private $Debug = false;

	// Set to true to disable all login functionality.
	private $LoginsDisabled = false;

	// The URL to initiate the session at the IdP. This should be "/Shibboleth.sso/Login".
	// This is handled by the SP on your server. The user will be redirected here upon login.
	// This cannot have any GET params due to get_initiator_url().
	private $SessionInitiatorURL = '/Shibboleth.sso/Login';

	// Logout URL. Handled by the SP on your server. This should be "/Shibboleth.sso/Logout"
	// and can have an optional "?return=$URL" to redirect to a custom logout page.
	// Eg: /Shibboleth.sso/Logout?return=/blog/2016/11/close-your-browser/
	private $SessionLogoutURL = '/Shibboleth.sso/Logout';

	// A URL for the 'Change Password' link for users.
	// Set to an empty string to disable this link.
	private $PassChangeURL = 'http://example.com/accounts';

	// "Lost Password" URL. Required.
	private $LostPassURL = 'http://example.com/accounts';

	//
	// END SETTINGS
	//

	public function __construct() {
		// Remove all existing wordpress authentication methods.
		remove_all_filters('authenticate');

		// Hide password fields on profile.php and user-edit.php
		add_filter('show_password_fields', '__return_false');

		// Do not allow password resets within WP.
		add_filter('allow_password_reset', '__return_false');

		// Change the lost password URL.
		add_action('login_form_lostpassword', array($this, 'lost_password'));

		// Add our Shib auth function to WordPress's authentication workflow.
		add_filter('authenticate', array($this, 'authenticate_or_redirect'), 10, 3);

		// Bypass the logout confirmation and redirect to $SessionLogoutURL defined above.
		add_action('login_form_logout', array($this, 'shib_logout'));

		// Check for IdP sessions that have disappeared.
		// The init hooks fire when WP is finished loading on every page, but before
		// headers are sent. We have to run confirm_shib_session() in the init hook
		// instead of in the plugin construct because is_user_logged_in() only works
		// after WP is finished loading.
		add_action('init', array($this, 'confirm_shib_session'));

		// Add hooks related to the user profile page.
		add_action('admin_init', array($this, 'add_admin_hooks'));
	}

	// Send the "lost password" link to the defined location.
	public function lost_password() {
		wp_redirect($this->LostPassURL);
		exit();
	}

	// This function is run on the WordPress login page.
	// Returns a WP_Error or a WP_User object.
	public function authenticate_or_redirect($user, $username, $password) {
		if (true === $this->LoginsDisabled) {
			return new WP_Error('shib', 'All logins are currently disabled.');
		}

		// Logged in at IdP and WP. Redirect to /.
		// TODO: Add a setting for a custom redirect path?
		if (true === is_user_logged_in() && true === $this->shib_session_active()) {
			if ($this->Debug) error_log('Shibboleth Debug: auth_or_redirect(): Logged in at WP and IdP. Redirecting to /.');
			wp_redirect('/');
			exit();
		}

		// Logged in at IdP but not WP. Login to WP.
		if (false === is_user_logged_in() && true === $this->shib_session_active()) {
			if ($this->Debug) error_log('Shibboleth Debug: auth_or_redirect(): Logged in at IdP but not WP.');
			return $this->login_to_wp();
		}

		// Logged in nowhere. Redirect to IdP login page.
		if ($this->Debug) error_log('Shibboleth Debug: auth_or_redirect(): Logged in nowhere!');
		if (isset($_GET['redirect_to'])) { // Avoid an 'unset variable' warning.
			wp_redirect($this->get_initiator_url($_GET['redirect_to']));
		} else {
			wp_redirect($this->get_initiator_url());
		}
		exit();

		// The case of 'logged in at WP but not IdP' is handled in 'init' via
		// confirm_shib_session().
	}

	// Check if a Shibboleth session is active. This means the user has logged into the IdP successfully.
	// This checks for the shibboleth HTTP headers. These headers cannot be forged because they actually
	// are generated locally in shibd via Apache's mod_shib. If the user spoofs the "mail" header,
	// for example, it actually shows up as HTTP_MAIL instead of "mail".
	// Returns true or false.
	private function shib_session_active() {
		if (isset($_SERVER['AUTH_TYPE']) && $_SERVER['AUTH_TYPE'] == 'shibboleth' &&
			isset($_SERVER['Shib-Session-ID']) && !empty($_SERVER['Shib-Session-ID']) &&
			isset($_SERVER['uid']) && !empty($_SERVER['uid']) &&
			isset($_SERVER['givenName']) && !empty($_SERVER['givenName']) &&
			isset($_SERVER['sn']) && !empty($_SERVER['sn']) &&
			isset($_SERVER['mail']) && !empty($_SERVER['mail'])) {

			return true;
		} else {
			return false;
		}
	}

	// Generate the URL to initiate Shibboleth login.
	// This takes in mind the site the user is logging in on
	// as well as the redirect_to GET value.
	private function get_initiator_url($RedirectTo = null) {

		// TODO: Is this necessary?
		switch_to_blog(get_current_blog_id()); // Switch to the site currently being viewed.
		$ReturnTo = site_url('wp-login.php'); // Get the login page URL.
		restore_current_blog(); // Switch back.

		if (!empty($RedirectTo)) {
			// Don't urlencode($RedirectTo) - we do this below.
			$ReturnTo = add_query_arg('redirect_to', $RedirectTo, $ReturnTo);
		}

		$InitiatorURL = $this->SessionInitiatorURL . '?target=' . urlencode($ReturnTo);

		return $InitiatorURL;
	}

	// Log a user into WP locally. This is called from authenticate_or_redirect().
	// If this is the first time we've seen this user, a new WP account will be created.
	// Exiting users will have their data updated based on the Shib headers.
	private function login_to_wp() {
		// The headers have been confirmed to be !empty() in shib_session_active() above.
		// The data is coming from the IdP, not the user, so lets trust it.
		$Shib['Username'] = $_SERVER['uid'];
		$Shib['FirstName'] = $_SERVER['givenName'];
		$Shib['LastName'] = $_SERVER['sn'];
		$Shib['Email'] = $_SERVER['mail'];

		// Check to see if they exist locally.
		$UserObj = get_user_by('login', $Shib['Username']);

		// See https://developer.wordpress.org/reference/functions/wp_insert_user/
		$InsertUserData = array(
				// user_pass is irrelevant since we removed all internal WP auth functions.
				// However, if this plugin is ever disabled/removed, WP will revert back to using user_pass, so it has to be "safe."
				'user_pass'		=> sha1(microtime()),
				'user_login'	=> $Shib['Username'],
				'user_nicename'	=> $Shib['Username'],
				'user_email'	=> $Shib['Email'],
				'display_name'	=> $Shib['FirstName'] . " " . $Shib['LastName'],
				'nickname'		=> $Shib['Username'],
				'first_name'	=> $Shib['FirstName'],
				'last_name'		=> $Shib['LastName']
		);

		// If wp_insert_user() receives 'ID' in the array, it will update the user data of an existing account
		// instead of creating a new account.
		// Also, return slightly different error messages below based on if we're updating an account or creating an account.
		// This is to aid debugging any issues/tickets that may occur.
		if (false !== $UserObj && is_numeric($UserObj->ID)) {
			$InsertUserData['ID'] = $UserObj->ID;
			$ErrorMsg = 'syncing';
		} else {
			$ErrorMsg = 'creating';
		}

		$NewUser = wp_insert_user($InsertUserData);

		// wp_insert_user() returns either int of the userid or WP_Error object.
		if (is_wp_error($NewUser) || !is_int($NewUser)) {
			do_action('wp_login_failed', $Shib['Username']); // Fire any login-failed hooks.

			// TODO: Setting for support ticket URL.
			return new WP_Error('shib', '<strong>ERROR:</strong> credentials are correct, but an error occurred ' . $ErrorMsg . ' the local account. Please open a support ticket with this error.');
		} else {
			// Created the user successfully.
			return new WP_User($NewUser);
		}
	}

	// Bypass the "are you sure" prompt when logging out and
	// redirect to the Shibboleth logout URL.
	// TODO: Is this still needed?
	public function shib_logout() {
		wp_logout();
		wp_redirect($this->SessionLogoutURL);
		exit();
	}

	// If the Shib session disappears while the user is logged into WP, log them out.
	// Hooked on 'init'.
	public function confirm_shib_session() {
		if (true === is_user_logged_in() && false === $this->shib_session_active()) {
			if ($this->Debug) error_log('Shibboleth Debug: confirm_shib_session(): Logged in at WP but not IdP. Logging out!');
			wp_logout();
			wp_redirect('/');
			exit();
		}
	}

	//
	// The functions below here are related to the user profile page.
	//

	// Various hooks for the admin/user profile screen. Hooked on 'admin_init'.
	public function add_admin_hooks() {
		// 'show_user_profile' fires after the "About Yourself" section when a user is editing their own profile.
		if (!empty($this->PassChangeURL)) add_action('show_user_profile', array($this, 'add_password_change_link'));

		// Run a hook to disable certain HTML form fields on when editing your own profile and for admins
		// editing other users' profiles.
		add_action('admin_footer-profile.php', array($this, 'disable_profile_fields'));
		add_action('admin_footer-user-edit.php', array($this, 'disable_profile_fields'));

		// Don't just mark the HTML form fields readonly, but handle the POST data as well.
		add_action('personal_options_update', array($this, 'disable_profile_fields_post'));
	}

	// Add another row at the bottom of the users' profile page that includes a password reset link.
	public function add_password_change_link() {
		echo '<table class="form-table"><tr>' . "\n";
		echo '<th>Change Password</th>' . "\n";
		echo '<td><a href="' . esc_url($this->PassChangeURL) . '">' . 'Change your password' . '</a></td>' . "\n";
		echo '</tr></table>' . "\n";
	}

	// Put some jquery in the footer that disables the html form fields for: first name, last name, nickname, and email.
	// NOTE: This just disables the forms, it doesn't handle the POST data. See disable_profile_fields_post() below.
	public function disable_profile_fields() {
		$Selectors = '#first_name,#last_name,#nickname,#email';

		// Use readonly instead of disabled because disabled fields are not included in the POST data.
		echo '<script type="text/javascript">jQuery(function() {' . "\n";
			echo 'jQuery("' . $Selectors . '").prop("readonly", true);' . "\n";

			// Add a notice to users that they cannot change certain profile fields.
			echo 'jQuery("#first_name").parents(".form-table").before("<div class=\"updated\"><p>Names and email addresses are centrally managed and cannot be changed from within WordPress.</p></div>");' . "\n";

		echo '});</script>';
	}

	// Don't just disable the HTML form fields; also make sure we handle the processing of POST data as well.
	// Script kiddies can use a DOM editor to re-enable the form fields manually.
	// TODO: This doesn't work perfectly. In my testing, I found problems with 'pre_user_email' not blocking email changes.
	// Since user data is updated from Shib upon every login, it really isn't a big deal. This may be a WP bug.
	public function disable_profile_fields_post() {
		add_filter('pre_user_first_name', function () { $UserObj = wp_get_current_user(); return $UserObj->first_name; });
		add_filter('pre_user_last_name', function () { $UserObj = wp_get_current_user(); return $UserObj->last_name; });
		add_filter('pre_user_nickname', function () { $UserObj = wp_get_current_user(); return $UserObj->user_nicename; });
		add_filter('pre_user_email', function () { $UserObj = wp_get_current_user(); return $UserObj->user_email; });
	}

} // End class

?>
