=== SimpleShib ===
Contributors: srg-1
Tags: shibboleth, authentication, sso, login
Requires at least: 4.6
Tested up to: 5.1
License: MIT

SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure.

== Description ==

**SimpleShib** is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure. The plugin is intended to be simple with easy-to-read code.

When a login request is received from a user, the Shibboleth session is validated. If the session does not exist, user is redirected to the IdP login page. Once authenticated at the IdP, the user is redirected back to WordPress and logged into their local WordPress account. If they do not have an existing local account, one can be automatically created for them.

Automatic account provisioning can optionally be disabled to restrict access to existing local WordPress users only.

User data (login, name, and email) is updated in WordPress from the IdP data upon every login. Additionally, the user is restricted from manually changing those fields on their profile page.

On multisite instances of WordPress, **SimpleShib** can only be network-activated.

**SimpleShib** is developed on GitHub. Please submit bug reports and contributions on [the GitHub project page](https://github.com/srguglielmo/SimpleShib).

For general support and questions, please use the [WordPress support forum](https://wordpress.org/support/plugin/simpleshib/).

This plugin is not affiliated with the Shibboleth or Internet2 organizations.

== Installation ==

This plugin will not work if you do not have a Shibboleth IdP and SP already configured. The `shibd` daemon must be installed, configured, and running on the same server as Apache/WordPress. Additionally, Apache's `mod_shib` module must be installed and enabled. These steps vary based on your operating system and environment. Installation and configuration of the IdP and SP is beyond the scope of this plugin's documentation. Reference the [official Shibboleth documentation](https://wiki.shibboleth.net).

1. Use a text editor to change the settings at the top of the `class-simple-shib.php` file. Each setting is described in the file.
2. Upload the directory to `wp-content/plugins/` (i.e. `wp-content/plugins/simpleshib/`).
3. Add the following to Apache's VirtualHost block and restart Apache:

`<Location />
	AuthType shibboleth
	Require shibboleth
</Location>
RewriteEngine on
RewriteCond %{REQUEST_URI} ^/Shibboleth.sso($|/)
RewriteRule . - [END]`

4. Activate the SimpleShib plugin.

== Frequently Asked Questions ==

= What is Shibboleth? =

From [Wikipedia](https://en.wikipedia.org/wiki/Shibboleth_(Internet2)):

> *"Shibboleth is a single sign-on (log-in) system for computer networks and the Internet. It allows people to sign in using just one identity to various systems run by federations of different organizations or institutions. The federations are often universities or public service organizations."*

= Can I test this without an IdP? =

Yes! Check out [TestShib.org](https://www.testshib.org/). Note, you still need the SP configured on the server with the httpd/WordPress.

= Why doesn't SimpleShib have feature x? =

I prefer the [KISS principle](https://en.wikipedia.org/wiki/KISS_principle). The less moving parts, the less of a chance something will break. If something does break, it's easier to fix.

= A shibboleth plugin already exists; why write another? =

My attempts to use the other Shibboleth plugin failed for various technical reasons. It seems to be unmaintained upstream. I ended up modifying the plugin heavily. I finally got to the point where I just wrote my own.

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

= 1.1.0 =
* Add a boolean setting for automatic account provisioning.
* Update example logout URL to return to the IdP's logout page.

= 1.0.3 =
* Compatibility with WordPress 5.1.
* Improved compliance with WordPress coding standards.
* Use wp_safe_redirect() when possible.
* Move PHP class into a separate file.
* Change install instructions from a must-use plugin to a network-activated plugin.

= 1.0.2 =
* Compatibility with WordPress 5.
* Improved compliance with WordPress coding standards.
* Minor documentation updates.

= 1.0.1 =
* Very minor documentation and code changes.
* Added plugin banner to assets.

= 1.0 =
* Initial release.
