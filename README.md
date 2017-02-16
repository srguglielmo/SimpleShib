# SimpleShib
SimpleShib is a WordPress plugin to authenticate users with a Shibboleth Single Sign-On infrastructure. SimpleShib handles authentication, not authorization. It follows the [KISS principle](https://en.wikipedia.org/wiki/KISS_principle).

When a login request is received from a user (`wp-login.php` or `wp-admin/`), the Shibboleth session is checked. If the session does not exist, user is redirected to the IdP login page. Once authenticated at the IdP, the user is redirected back to WordPress and logged into their WP account.

## Requirements
This plugin has been tested/developed on a WordPress 4.7 multisite running PHP 7.0 (via FPM) as a __mu-plugin__. It has not been tested and may not be compatible (yet) with other configurations.

Note, this plugin will __not work__ if you do not have a IdP and SP already configured. Setting up the IdP and SP are beyond the scope of this plugin. Reference the [official Shibboleth documentation](https://wiki.shibboleth.net).

## Documentation
Please see `readme.txt`.

## Contributing
Please use GitHub issues for any questions or contributions. Contributions will be added under the MIT license. By submitting a pull request, you agree to this licensing.

1. Fork the repository.
2. Create a local branch for your change(s).
3. Commit your changes and push your created branch to your fork.
4. Open a new pull request into our master branch.
