# SimpleShib
SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure. SimpleShib handles authentication, not authorization. The plugin is kept as simple as possible.

## Workflow
When a login request is received from a user (`wp-login.php` or `wp-admin/`), the Shibboleth session is verified. If the session does not exist, user is redirected to the IdP login page. Once authenticated at the IdP, the user is redirected back to WordPress and logged into their WP account. If they do not have an existing account, one is created for them.

User data (first name, last name, email) is updated in WordPress's database from the IdP data upon every login.

## Requirements
This plugin has been tested as a __mu-plugin__ on WordPress 4.7 multisite running Apache and PHP 7.0 (via FPM). It has not been tested and may not be compatible with other configurations (yet).

This plugin will __not work__ if you do not have a IdP and SP already configured. Installation and configuration of the IdP and SP is beyond the scope of this plugin. Reference the [official Shibboleth documentation](https://wiki.shibboleth.net).

## Documentation
Please see `readme.txt`.

## Contributing
Please use GitHub issues for any questions or contributions. Contributions will be added under the [MIT license](https://choosealicense.com/licenses/mit/). By submitting a pull request, you agree to this licensing.

1. Fork the repository.
2. Create a local branch for your change(s).
3. Commit your changes and push your created branch to your fork.
4. Open a new pull request into our master branch.
