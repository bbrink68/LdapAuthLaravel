<?php 

namespace Mattbrown\Ldapauth;

use Config;
use Exception;
use Illuminate\Auth\GenericUser;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Connection;

/**
 * An OpenLDAP authentication driver for Laravel 4.
 *
 * @author Matt Brown <bbrink68@gmail.com>
 * @author Yuri Moens <yuri.moens@gmail.com>
 *
 */

class LdapauthUserProvider implements UserProvider {

    /**
     * The Eloquent user model.
     *
     * @var  string
     */
    protected $model;

    /**
     * The LDAP connection.
     *
     * @var ldap link
     */
    protected $conn;

    /**
     * The active database connection.
     *
     * @param  \Illuminate\Database\Connection
     */
    protected $dbConn;

    /**
     * Create a new LDAP user provider.
     * 
     * @param 
     */
    public function __construct(Connection $dbConn)
    {
        // Get DB Connection
        $this->dbConn = $dbConn;

        // Get Configurations
        $config = $this->getConfig();
        
        // Check for existence of ldap extension
        if (! extension_loaded('ldap')) {
            if ($config['debug']) {
                throw new Exception("PHP LDAP extension not loaded.");
            }
        }

        // Check for good connection to host
        if (! $this->conn = ldap_connect("ldap://{$config['host']}")) {
            if ($config['debug']) {
                throw new Exception(
                    "Could not connect to LDAP host {$config['host']}: " . ldap_error($this->conn)
                );
            }
        }

        // Setup some LDAP options
        ldap_set_option($this->conn, LDAP_OPT_PROTOCOL_VERSION, $config['version']);
        ldap_set_option($this->conn, LDAP_OPT_REFERRALS, 0);


        // If Required Configs Present
        if ($config['username'] && $config['password'] && $config['rdn'] ) {

            // Attempt to Bind
            if (! @ldap_bind(
                    $this->conn,
                    "uid={$config['username']},{$config['rdn']}", 
                    $config['password']
                )
            ) {
                // No Good, Toss User an Exception
                if ($config['debug']) {
                    throw new Exception('Could not bind to AD: ' . ldap_error($this->conn));
                }
            }

        // Else No Config Data
        } else {

            // Attempt Without User/Pass/RDN
            if (! @ldap_bind($this->conn)) {

                // No Bind, Throw Exception
                if ($config['debug']) {
                    throw new Exception('Could not bind to AD: ' . ldap_error($this->conn));
                }
            }
        }
    }

    /**
     * Clean up the LDAP connection.
     */
    public function __destruct()
    {
        if (! is_null($this->conn)) {
            ldap_unbind($this->conn);
        }
    }

    /**
     * Get Config Settings
     */
    public function getConfig()
    {
        return [
            'debug' => config('ldap.debug'),                    //Config::get('ldapauth::debug'),
            'host' => config('ldap.host'),                      //Config::get('ldapauth::host'),
            'version' => config('ldap.version'),                //Config::get('ldapauth::version'),
            'username' => config('ldap.username'),              //Config::get('ldapauth::username'),
            'password' => config('ldap.password'),              //Config::get('ldapauth::password'),
            'rdn' => config('ldap.rdn'),                        //Config::get('ldapauth::rdn'),
            'use_db' => config('ldap.use_db'),                  //Config::get('ldapauth::use_db'),
            'ldap_field' => config('ldap.ldap_field'),          //Config::get('ldapauth::ldap_field'),
            'db_table' => config('ldap.db_table'),              //Config::get('ldapauth::db_table'),
            'db_field' => config('ldap.db_field'),              //Config::get('ldapauth::db_field'),
            'eloquent' => config('ldap.eloquent'),              //Config::get('ldapauth::eloquent'),
            'login_attr' => config('ldap.login_attribute'),     //Config::get('ldapauth::login_attribute'),
            'user_id_attr' => config('ldap.user_id_attribute'), //Config::get('ldapauth::user_id_attribute'),
            'basedn' => config('ldap.basedn'),                  //Config::get('ldapauth::basedn'),
            'filter' => config('ldap.filter'),                  //Config::get('ldapauth::filter'),
            'user_attrs' => config('ldap.user_attributes'),     //Config::get('ldapauth::user_attributes'),
            'user_model' => config('ldap.eloquent_user_model')  //Config::get('ldapauth::eloquent_user_model')
        ];
    }


    /**
     * Retrieve a user by their unique identifier.
     * 
     * @param  mixed $identifier
     * @return \Illuminate\Auth\UserInterface|null
     */
    public function retrieveById($identifier)
    {
        // Get Configurations
        $config = $this->getConfig();

        // If We Found Entries
        if ($entries = $this->searchLdap($identifier)) {

            // Are we Using DB As Well?
            if ($config['use_db']) {

                // Grab User Row From DB
                $ldapValue = $entries[0][$config['ldap_field']][0];

                $user = $this->dbConn
                    ->table($config['db_table'])
                    ->where($config['db_field'], '=', $ldapValue)
                    ->first();

                // If User Wants Eloquent User
                if ($config['eloquent']) {
                    return $this->createModel()
                        ->newQuery()
                        ->find($user->id);

                // If User Wants Generic User
                } else {
                    return new GenericUser(get_object_vars($user));
                }

            // Not Using DB - Create Generic from LDAP
            } else {
                return $this->createGenericUserFromLdap($entries[0]);
            }
        }        
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     * 
     * @param  mixed $identifier
     * @param  string $token
     * @return UserProvider|null
     */
    public function retrieveByToken($identifier, $token)
    {
        $config = $this->getConfig();

        // If We Found Entries
        if ($entries = $this->searchLdap($identifier)) {

            $ldapValue = $entries[0][$config['ldap_field']][0];
            
            $user = $this->dbConn
                ->table($config['db_table'])
                ->where($config['db_field'], '=', $ldapValue)
                ->first();

            $model = $this->createModel();

            // Return Model
            return $model->newQuery()
                ->where('id', $user->id)
                ->where($model->getRememberTokenName(), $token)
                ->first();
        } 
    }

    /**
     * Update the "remember me" token for the given user in storage.
     * 
     * @param  Authenticatable $user
     * @param  string $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        // If Eloquent User
        if (! $user instanceof GenericUser) {
            
            // Update Remember Me Token
            $user->setAttribute($user->getRememberTokenName(), $token);
            $user->save();
        }
    }

    /**
     * Retrieve a user by the given credentials.
     * 
     * @param  array  $credentials
     * @return UserProvider|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        $config = $this->getConfig();

        // Search
        $result = @ldap_search(
            $this->conn, 
            "{$config['login_attr']}={$credentials['username']},{$config['basedn']}",
            $config['filter']
        );
        
        // Return if Not Found
        if ($result == false) {
            return;
        }

        // Found, Verify We Only Have One
        $entries = ldap_get_entries($this->conn, $result);
        if ($entries['count'] == 0 || $entries['count'] > 1) {
            return;
        }

        // Create Model From Entry
        $this->model = $this->createGenericUserFromLdap($entries[0]);

        return $this->model;
    }

    /**
     * Validate a user against the given credentials.
     * 
     * @param  Authenticatable $user
     * @param  array
     * @return boolean
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        $config = $this->getConfig();

        // Check Good Data Was Given
        if ($user == null) {
            return false;
        }

        if (isset($credentials['password']) == '') {
            return false;
        }

        // Check Credentials By Attempting to Bind
        if (! $result = @ldap_bind(
            $this->conn, 
            "{$config['login_attr']}={$credentials['username']},{$config['basedn']}",
            $credentials['password']
        )) {            
            return false;
        }

        // Good Auth Otherwise
        return true;
    }

    /**
     * Search the LDAP server for entries that match the specified identifier.
     * 
     * @param  mixed $identifier
     * @return array|null
     */
    private function searchLdap($identifier)
    {
        // Grab Some Config
        $config = $this->getConfig();
        $filter = $config['filter'];
        
        // Normalize Filter
        if (strpos($filter, '&')) {

            $filter = substr_replace(
                $filter, 
                "({$config['user_id_attr']}={$identifier})", 
                strpos($filter, '&') + 1, 0
            );

        } else {
            $filter = "(&({$config['user_id_attr']}={$identifier}){$filter})";
        }

        // Run Search
        $result = @ldap_search($this->conn, $config['basedn'], $filter);

        // Return Early if No Hits
        if (! $result) {
            return;
        }

        // Good Return, Verfiy Only 1 Returned
        $entries = ldap_get_entries($this->conn, $result);
        if ($entries['count'] == 0 || $entries['count'] > 1) {
            return;
        }

        // Return Single Entry
        return $entries;
    }

    /**
     * Create a GenericUser from the specified LDAP entry.
     * 
     * @param  array $entry
     * @return \Illuminate\Auth\GenericUser
     */
    private function createGenericUserFromLdap($entry)
    {
        // Grab Some Config
        $config = $this->getConfig();

        // Set ID
        $parameters = [ 'id' => $entry[$config['user_id_attr']][0] ];

        // Iterate Over Desired User Attributes
        foreach ($config['user_attrs'] as $key => $value) {
            // Set Attribute To What Was In LDAP
            $parameters[$value] = $entry[$key][0];
        }

        // Return User
        return new GenericUser($parameters);
    }

    /**
     * Create a new model instance.
     * 
     * @return \Illuminate\Database\Eloquent\Model
     */
    private function createModel()
    {
        // Grab Some Config
        $config = $this->getConfig();

        $class = '\\' . ltrim($config['user_model'], '\\');

        return new $class;
    }
}
