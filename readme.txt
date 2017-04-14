=== SimpleShib ===
Contributors: srg-1
Tags: shibboleth, authentication, sso, login
Requires at least: 4.6
Tested up to: 4.7.3
Stable tag: trunk
License: MIT
License URI: https://choosealicense.com/licenses/mit/

SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure.

== Description ==

**SimpleShib** is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure. The plugin is intended to be simple with easy-to-read code.

When a login request is received from a user, the Shibboleth session is validated. If the session does not exist, user is redirected to the IdP login page. Once authenticated at the IdP, the user is redirected back to WordPress and logged into their WordPress account. If they do not have an existing account, one is created for them automatically.

User data (login, name, and email) is updated in WordPress from the IdP data upon every login. Additionally, the user is restricted from editing those fields on their profile page.

This plugin has been tested as a mu-plugin on WordPress 4.7 multisite running Apache and PHP 7.0 (via FPM). It has not been tested and may not be compatible with other configurations (yet). Please report if you have tested this on a different setup.

**SimpleShib** is actively developed on GitHub. Please submit bug reports and contributions on [the GitHub project page](https://github.com/srguglielmo/SimpleShib).

For general support and questions, please use the [WordPress support forum](https://wordpress.org/support/plugin/simpleshib/).

This plugin is not affiliated with the Shibboleth or Internet2 organizations.

== Installation ==

This plugin will not work if you do not have a Shibboleth IdP and SP already configured. The `shibd` daemon must be installed, configured, and running on the same server as the httpd/WordPress. Additionally, Apache's `mod_shib` module must be installed and enabled. These steps vary based on your operating system and environment. Installation and configuration of the IdP and SP is beyond the scope of this plugin's documentation. Reference the [official Shibboleth documentation](https://wiki.shibboleth.net).

1. Use a text editor to change the settings at the top of the `simpleshib.php` file. Each setting is described in the file.
2. Upload the `simpleshib.php` file to the `/wp-content/mu-plugins/` directory.
3. Add the following to Apache's VirtualHost block and restart Apache:

	<Location />
		AuthType shibboleth
		Require shibboleth
	</Location>

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

= HTTP requests to Shibboleth.sso are showing WordPress's "Page Not Found" error =

You must configure Apache to handle requests for `/Shibboleth.sso/` instead of letting WordPress handle it. Apache will pass the request to `mod_shib`/`shibd`. To do this, add the following configuration to your VirtualHost block in Apache and restart the httpd:

	RewriteEngine on
	RewriteCond %{REQUEST_URI} ^/Shibboleth.sso($|/)
	RewriteRule . - [END]

= The doman name is not correct after a redirect =

Add the following to Apache's global config:

	UseCanonicalName On

= Can I automatically set user roles based on IdP data?  =

No. **SimpleShib** handles authentication, not authorization. Authorization is managed within WordPress by network admins or site admins.

= What's this MIT license? =

**SimpleShib** is released under the [MIT license](https://choosealicense.com/licenses/mit/). The MIT license is short, simple, and very permissive. Basically, you can do whatever you want, provided the original copyright and license notice are included in any/all copies of the software. You may modify, distribute, sell, incorporate into proprietary software, use privately, and use commerically.

There is no warranty and the author or any contributors are not liable if something goes wrong.

See the `LICENSE` file for full details.

== Changelog ==

= 1.0.1 =
* Very minor documentation and code changes.
* Added plugin banner to assets.

= 1.0 =
* Initial release.
