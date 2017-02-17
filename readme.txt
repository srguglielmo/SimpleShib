=== SimpleShib ===
Contributors: srg-1
Tags: shibboleth, authentication, sso, login
Requires at least: 4.6
Tested up to: 4.7.2
Stable tag: trunk
License: MIT
License URI: https://choosealicense.com/licenses/mit/

SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure.

== Description ==

SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure. SimpleShib handles authentication, not authorization. The plugin is kept as simple as possible.

When a login request is received from a user (`wp-login.php` or `wp-admin/`), the Shibboleth session is verified. If the session does not exist, user is redirected to the IdP login page. Once authenticated at the IdP, the user is redirected back to WordPress and logged into their WP account. If they do not have an existing account, one is created for them.

User data (first name, last name, email) is updated in WordPress's database from the IdP data upon every login.

This plugin has been tested as a mu-plugin on WordPress 4.7 multisite running Apache and PHP 7.0 (via FPM). It has not been tested and may not be compatible with other configurations (yet).

== Installation ==

This plugin will not work if you do not have a Shibboleth IdP and SP already configured. The `shibd` daemon must be installed, configured, and running on the same server as the httpd. Additionally, Apache's mod_shib module must be installed and enabled. These steps vary based on your operating system and environment. Installation and configuration of the IdP and SP is beyond the scope of this plugin's documentation. Reference the [official Shibboleth documentation](https://wiki.shibboleth.net).

1. Use a text editor to change the settings at the top of the `simpleshib.php` file. Each setting is described in the file.
2. Upload the `simpleshib.php` file to the `/wp-content/mu-plugins/` directory.
3. Add the following to Apache's VirtualHost block and restart Apache:

<Location />
	AuthType shibboleth
	Require shibboleth
</Location>

== Frequently Asked Questions ==

= Requests to /Shibboleth.sso/ are showing a WordPress "Page Not Found" error! =

You must configure Apache to handle requests for `/Shibboleth.sso/` instead of letting WordPress handle it. Apache will past the request to mod_shib and shibd. To do this, add the following configuration to your VirtualHost block in Apache:

RewriteEngine on
RewriteCond %{REQUEST_URI} ^/Shibboleth.sso($|/)
RewriteRule . - [END]

= I'm having domain name redirect issues. =

Add the following to Apache's global config:

UseCanonicalName On

== Changelog ==

= 1.0 =
* Inital release.
