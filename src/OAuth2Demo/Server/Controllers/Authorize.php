<?php

namespace OAuth2Demo\Server\Controllers;

use Silex\Application;

class Authorize
{
    
    /**
     * Connects the routes in Silex
     * @param type $routing
     */
    public static function addRoutes($routing)
    {
        $routing->get('/authorize', array(new self(), 'authorize'))->bind('authorize');
        $routing->post('/authorize', array(new self(), 'authorizeFormSubmit'))->bind('authorize_post');
        $routing->get('/authorize_client', array(new self(), 'authorizeImplicitGrant'))->bind('authorize_implicit');
    }

    /**
     * The user is directed here by the client in order to authorize the client app to access his/her data
     * @param \Silex\Application $app
     * @return type
     */
    public function authorize(Application $app)
    {
        // get the oauth server (configured in src/OAuth2Demo/Server/Server.php)
        $server = $app['oauth_server'];

        // validate the authorize request.  if it is invalid, redirect back to the client with the errors in tow
        if (!$server->validateAuthorizeRequest($app['request'])) {
            return $server->getResponse();
        }

        // dispaly the "do you want to authorize?" form
        return $app['twig']->render('server/authorize.twig', array('client_id' => $app['request']->query->get('client_id'), 'scope' => $app['request']->query->get('scope')));
    }

    /**
     * This is called once the user decides to authorize or cancel the client app's authorization request
     * @param \Silex\Application $app
     * @return type
     */
    public function authorizeFormSubmit(Application $app)
    {
        // get the oauth server (configured in src/OAuth2Demo/Server/Server.php)
        $server = $app['oauth_server'];

        // check the form data to see if the user authorized the request
        $authorized = (bool) $app['request']->request->get('authorize');

        // call the oauth server and return the response
        return $server->handleAuthorizeRequest($app['request'], $authorized);
    }
    
    public function authorizeImplicitGrant(Application $app)
    {
     
        // get the oauth server (configured in src/OAuth2Demo/Server/Server.php)
        $server = $app['oauth_server'];

        // call the oauth server and return the response
        $return = $server->handleAuthorizeRequest($app['request'], true);
        
        return $return;
    }
}
