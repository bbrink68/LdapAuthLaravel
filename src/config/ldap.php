<?php

/**
 * LDAP configuration for mbrown/ldapauth
 */

return array(
    // Host
    'host' => 'ldap.example.com',

    // RDN used by the user configured below (Optional)
    'rdn' => 'ou=System,dc=example,dc=com',

    // Username & Password (Optional)
    'username' => 'username',
    'password' => 'thisisasecret',
    
    // LDAP protocol version (2 or 3)
    'version'  => '3',   

    // User Filter (Optional)
    'filter' => '(&(objectclass=posixAccount)(|(status=member)))',

    // Login attributes for users
    'login_attribute' => 'uid', 

    // Base DN
    'basedn' => 'ou=people,dc=example,dc=com', 

    // Attribute name containg the uid number
    'user_id_attribute' => 'uidNumber',

    // The ldap attributes you want to store 
    // in session (ldap_attr => array_field_name)
    'user_attributes' => array(
        'uid' => 'username',
    ),

    // Pull Extra Info From DB
    'use_db' => true,

    // Required if use_db
    // LDAP field we want to compare to the db_field to find our user
    'ldap_field' => 'uid',
    'db_connection' => null,
    'db_table' => 'users',

    // DB field we want to compare to the ldap_field to find our user
    'db_field' => 'user_name',

    // Use Eloquent instead of Generic
    'eloquent' => true,

    // User Model
    'eloquent_user_model' => 'User',

    // Debug?
    'debug' => true, 
);
