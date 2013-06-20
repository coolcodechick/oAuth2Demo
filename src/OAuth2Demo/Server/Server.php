<?php

namespace OAuth2Demo\Server;

use Silex\Application;
use Silex\ControllerProviderInterface;
use OAuth2\HttpFoundationBridge\Server as OAuth2_HttpFoundationServer;
 //added for scope
use OAuth2_Storage_Memory;
use OAuth2_Scope;

class Server implements ControllerProviderInterface
{
    /**
     * function to create the OAuth2 Server Object
     * @param \Silex\Application $app
     */
    public function setup(Application $app)
    {
        // ensure our Sqlite database exists
        if (!file_exists($sqliteFile = __DIR__.'/../../../data/oauth.sqlite')) {
            $this->generateSqliteDb();
        }

        // create PDO-based sqlite storage
        //$storage = new \OAuth2_Storage_Pdo(array('dsn' => 'sqlite:'.$sqliteFile));
        // Switch storage to a MySQL Database
        $storage = new \OAuth2_Storage_Pdo(array('dsn' => 'mysql:host=localhost;dbname=oauth2_server_php', 'username' => 'root', 'password' => 'root'));

        // use HttpFountation Server, which returns a silex-compatible request object
        // (https://github.com/bshaffer/oauth2-server-httpfoundation-bridge)
        // To override the default settings for the configurations pass them as an array in the second param
        $server = new OAuth2_HttpFoundationServer($storage, array('enforce_state' => false , 'allow_implicit' => true, 'access_lifetime' => 30 /*3600*/, 'refresh_token_lifetime' => 75 /*1209600*/));

        // we only need "AuthorizationCode" grant type for this demo (we should show off all grant types eventually!)
        $grantType = new \OAuth2_GrantType_AuthorizationCode($storage);
        $server->addGrantType($grantType);

        // Add additional grant types
        $server->addGrantType(new \OAuth2_GrantType_ClientCredentials($storage));
    
        //False is default set to true to receive refresh token every time
        $config = array('always_issue_new_refresh_token' => false);
        $server->addGrantType(new \OAuth2_GrantType_RefreshToken($storage, $config));

        $server->addGrantType(new \OAuth2_GrantType_UserCredentials($storage));

        // Set up the scopes available
        $defaultScope = 'basic';
        $supportedScopes = array(
            'basic',
            'profile',
            'friends'
        );

        $memory = new OAuth2_Storage_Memory(
            array(
                'default_scope' => $defaultScope,
                'supported_scopes' => $supportedScopes
            )
        );
        $scopeUtil = new OAuth2_Scope($memory);

        $server->setScopeUtil($scopeUtil);

        // add the server to the silex "container" so we can use it in our controllers
        // (see src/OAuth2Demo/Server/Controllers/.*)
        $app['oauth_server'] = $server;
    }

    /**
     * Connect the controller classes to the routes
     * @param \Silex\Application $app
     * @return \Silex\Application
     */
    public function connect(Application $app)
    {
        // create the oauth2 server object
        $this->setup($app);

        // creates a new controller based on the default route
        $routing = $app['controllers_factory'];

        /* Set corresponding endpoints on the controller classes */
        Controllers\Authorize::addRoutes($routing);
        Controllers\Token::addRoutes($routing);
        Controllers\Resource::addRoutes($routing);

        return $routing;
    }

    private function generateSqliteDb()
    {
        include_once(__DIR__.'/../../../data/rebuild_db.php');
    }
}
