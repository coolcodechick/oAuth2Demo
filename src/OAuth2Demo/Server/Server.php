<?php

namespace OAuth2Demo\Server;

use Silex\Application;
use Silex\ControllerProviderInterface;
use OAuth2\HttpFoundationBridge\Server as OAuth2_HttpFoundationServer;

class Server implements ControllerProviderInterface
{
    /**
     * function to create the OAuth2 Server Object
     */
    public function setup(Application $app)
    {
        // ensure our Sqlite database exists
        if (!file_exists($sqliteFile = __DIR__.'/../../../data/oauth.sqlite')) {
            $this->generateSqliteDb();
        }

        // create PDO-based sqlite storage
        //$storage = new \OAuth2_Storage_Pdo(array('dsn' => 'sqlite:'.$sqliteFile));
        $storage = new \OAuth2_Storage_Pdo(array('dsn' => 'mysql:host=localhost;dbname=oauth2_server_php', 'username' => 'root', 'password' => 'root'));

        // use HttpFountation Server, which returns a silex-compatible request object (https://github.com/bshaffer/oauth2-server-httpfoundation-bridge)
        $server = new OAuth2_HttpFoundationServer($storage, array('enforce_state' => true));

        // we only need "AuthorizationCode" grant type for this demo (we should show off all grant types eventually!)
        $grantType = new \OAuth2_GrantType_AuthorizationCode($storage);
        $server->addGrantType($grantType);

        // add the server to the silex "container" so we can use it in our controllers (see src/OAuth2Demo/Server/Controllers/.*)
        $app['oauth_server'] = $server;
    }

    /**
     * Connect the controller classes to the routes
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