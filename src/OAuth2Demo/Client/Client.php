<?php

namespace OAuth2Demo\Client;

use Silex\Application;
use Silex\ControllerProviderInterface;

class Client implements ControllerProviderInterface
{
    /**
     * Creates a new controller based on the default route and add routes
     * @param \Silex\Application $app
     * @return \Silex\Application
     */
    public function connect(Application $app)
    {
        // creates a new controller based on the default route
        $routing = $app['controllers_factory'];

        /* Set corresponding endpoints on the controller classes */
        Controllers\Homepage::addRoutes($routing);
        Controllers\ReceiveAuthorizationCode::addRoutes($routing);
        Controllers\RequestToken::addRoutes($routing);
        Controllers\RequestResource::addRoutes($routing);
        Controllers\ImplicitGrant::addRoutes($routing);     //add new class to routing
        Controllers\ClientCredential::addRoutes($routing);     //add new class to routing
        Controllers\UserCredential::addRoutes($routing);     //add new class to routing

        return $routing;
    }
}
