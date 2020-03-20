=== SimpleShib ===
Contributors: srg-1
Tags: shibboleth, authentication, sso, login
Requires at least: 4.6
Tested up to: 5.3
License: MIT

SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure.

== Description ==

**SimpleShib** is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure. This plugin will not work if you do not have a Shibboleth IdP and SP already configured.

When a WordPress login request is received from a user, the Shibboleth session is validated. If the session does not exist, user is redirected to the IdP login page. Once authenticated at the IdP, the user is redirected back to WordPress and logged into their local WordPress account. If a local account does not exist, one can _optionally_ be created.

User data (login, name, and email) is updated in WordPress from the IdP data upon every login. Additionally, the user is restricted from manually changing those fields on their profile page.

On multisite instances of WordPress, **SimpleShib** can only be network-activated.

The plugin settings include options for autoprovisioning, IdP attributes, password reset/change URLs, and session initiation/logout URLs.

**SimpleShib** is developed on GitHub. Please submit bug reports and contributions on [the GitHub project page](https://github.com/srguglielmo/SimpleShib). For general support and questions, please use the [WordPress support forum](https://wordpress.org/support/plugin/simpleshib/).

This plugin is not affiliated with the Shibboleth or Internet2 organizations.

== Installation ==

This plugin will not work if you do not have a Shibboleth IdP and SP already configured. The `shibd` daemon must be installed, configured, and running on the same server as Apache/WordPress. Additionally, Apache's `mod_shib` module must be installed and enabled. These steps vary based on your operating system and environment. Installation and configuration of the IdP and SP is beyond the scope of this plugin's documentation. Reference the [official Shibboleth documentation](https://wiki.shibboleth.net/confluence/display/SP3/Home).

1. Install the plugin to `wp-content/plugins/simpleshib` via your normal plugin install method (download and extract ZIP, `wp plugin install`, etc).
2. Add the following to Apache's VirtualHost block and restart Apache. This will ensure the shibd daemon running on your server will handle `/Shibboleth.sso/` requests instead of WordPress.

	`<Location />
		AuthType shibboleth
		Require shibboleth
	</Location>
	RewriteEngine on
	RewriteCond %{REQUEST_URI} ^/Shibboleth.sso($|/)
	RewriteRule . - [END]`

3. Activate the SimpleShib plugin in WordPress.
4. Browse to Settings->SimpleShib and edit the configuration.

== Frequently Asked Questions ==

= What is Shibboleth? =

From [Wikipedia](https://en.wikipedia.org/wiki/Shibboleth_(Internet2)):

> *"Shibboleth is a single sign-on (log-in) system for computer networks and the Internet. It allows people to sign in using just one identity to various systems run by federations of different organizations or institutions. The federations are often universities or public service organizations."*

= Can I test this without an IdP? =

Maybe. Check out [TestShib.org](https://www.testshib.org/). Note, you still need the SP/shibd configured on the server with Apache/WordPress.

= A shibboleth plugin already exists; why write another? =

My attempts to use the other Shibboleth plugin failed for various technical reasons. It seemed to be unmaintained at the time. I ended up modifying the plugin heavily. I finally got to the point where I just wrote my own.

= The domain name is not correct after a redirect =

Add the following to Apache's config:

	`UseCanonicalName On`

= Can I automatically set user roles based on IdP data?  =

No. **SimpleShib** handles authentication, not authorization. Authorization is managed within WordPress by network admins or site admins.

= What's this MIT license? =

**SimpleShib** is released under the MIT license. The MIT license is short, simple, and very permissive. Basically, you can do whatever you want, provided the original copyright and license notice are included in any/all copies of the software. You may modify, distribute, sell, incorporate into proprietary software, use privately, and use commerically.

There is no warranty and the author or any contributors are not liable if something goes wrong.

See the `LICENSE` file for full details.

== Changelog ==

= 1.2.1 =
* Add options for custom IdP attributes.
* Documentation updates.

= 1.2.0 =
* Move configuration into the database.
* Compatibility with WordPress 5.3.
* Fix a return_to URL bug that affected multisite.
* Documentation updates.

= 1.1.1 =
* Compatibility with WordPress 5.2.
* Improve compliance with WordPress coding standards.
* Minor documentation updates.

= 1.1.0 =
* Add a boolean setting for automatic account provisioning.
* Update example logout URL to return to the IdP's logout page.

= 1.0.3 =
* Compatibility with WordPress 5.1.
* Improve compliance with WordPress coding standards.
* Use wp_safe_redirect() when possible.
* Move PHP class into a separate file.
* Change install instructions from a must-use plugin to a network-activated plugin.

= 1.0.2 =
* Compatibility with WordPress 5.
* Improve compliance with WordPress coding standards.
* Minor documentation updates.

= 1.0.1 =
* Minor documentation and code changes.
* Add plugin banner to assets.

= 1.0.0 =
* Initial release.
