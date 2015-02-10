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

`composer update`.

In `config/app.php`:

Add `'Mattbrown\Ldapauth\LdapauthServiceProvider'` to providers array.

`composer dump-auto`

Open `config/auth.php` and change the authentication driver to `ldap`.


## Configuration

Run `php artisan vendor:publish --provider="Mattbrown\Ldapauth\LdapauthServiceProvider"`, then find `app/config/ldap.php` and adjust the config file for your LDAP settings.

Profit Dollars.