# LDAP Authentication #
This is based off of [Yuri Moens L4OpenLdap Provider](https://github.com/yuri-moens/l4-openldap)

An OpenLDAP authentication driver for Laravel 4.

## Installation

Add the following to your `composer.json` file.

```json
require {
	"mattbrown/ldapauth": "dev-master"
}
```

Run `composer update`.

Open `app/config/app.php` and add:

`Mattbrown\Ldapauth\LdapauthServiceProvider`

Open `app/config/auth.php` and change the authentication driver to `ldap`.

## Configuration

Run `php artisan config:publish mattbrown/ldapauth` and adjust the config file for your LDAP settings.

It can be found in `app/config/packages/mattbrown/ldapauth`.