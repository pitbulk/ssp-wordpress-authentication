ssp-wordpress-authentication
============================

This repository contains code and documentation required to set wordpress as an authentication source for simpleSAMLphp IdP.


Installation
------------

Copy the sqlauthwp folder inside the simpleSAMLphp modules folder.


Configuration
-------------

At 'config/authsources.php' set an entry like:

```
    'wordpress-auth' => array(
        'sqlauthwp:SQL',
        'dsn' => 'mysql:host=<host>;dbname=<wordpress-database>',
        'username' => '<wordpressuser>',
        'password' => '<wordpresspassword>',
        'query' => 'SELECT user_login, user_nicename, user_email FROM wp_users WHERE user_login = :username',
        'query_pw' => 'SELECT user_pass FROM wp_users WHERE user_login = :username',
    ),
```

And replace <host>, <wordpress-database>, <wordpressuser> and <wordpresspassword> but your values.


Then access to metadata/saml20-idp-hosted.php and set
```
 'auth' => 'wordpress-auth',
```
