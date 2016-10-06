<?php

namespace Mattbrown\Ldapauth;

use Illuminate\Support\ServiceProvider;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Matt Brown <bbrink68@gmail.com>
 * @author Yuri Moens <yuri.moens@gmail.com>
 *
 */

class LdapauthServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var  boolean
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     *
     * @return void
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../../config' => config_path('/'),
        ]);

        $auth = \Auth::getFacadeRoot();

        if (method_exists($auth, 'provider')) {
            // If the provider method exists, we're running Laravel 5.2.
            // Register the ldap auth user provider.
            $auth->provider('ldap', function($app, array $config) {
                return new LdapauthUserProvider($app['db']->connection($app['config']->get('ldap.db_connection')));
            });
        } else {
            // Otherwise we're using 5.0 || 5.1
            // Extend Laravel authentication with ldap driver.
            $auth->extend('ldap', function ($app) {
                new LdapauthUserProvider($app['db']->connection($app['config']->get('ldap.db_connection')));
            });
        }
    }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {

    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return array('ldap');
    }
}
