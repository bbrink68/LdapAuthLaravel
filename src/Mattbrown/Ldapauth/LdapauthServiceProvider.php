<?php 

namespace Mattbrown\Ldapauth;

use Illuminate\Auth\Guard;
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
        $this->package('mattbrown/ldapauth');

        $this->app['auth']->extend('ldap', function ($app) {
            return new Guard(
                new LdapauthUserProvider($app['db']->connection()),
                $app->make('session.store')
            );
        });
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
