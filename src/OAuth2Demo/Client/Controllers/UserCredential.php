<?php

namespace OAuth2Demo\Client\Controllers;

use Silex\Application;
use OAuth2Demo\Shared\Curl;

/**
 * Uses an User Credential Grant Type uses the Client Credentials for an Access Token directly. 
 *
 * REQUEST : HttpRequest = POST
 *           REQUIRED : client_id       *** client credentials are passed in Authorization header ***
 *                      client_secret 
 *                      grant_type = "password" 
 *                      username       
 *                      password 
 *           OPTIONAL : scope
 *                      
 * RETURNS : Returns response and redirects with token in query string (ie. ?access_token=____&state=____ )
 *           REQUIRED : access_token
 *                      expires_in 
 *                      token_type = "bearer"
 *           refresh_token SHOULD NOT be issued
 * 
 * @author tanya brodsky
 */
class UserCredential
{
    /**
     * Connects the routes in Silex
     * @param type $routing
     */
    public static function addRoutes($routing)
    {
        $routing->get('/user_grant', array(new self(), 'userGrant'))->bind('user_grant');
    }
    
    /**
     * Passes the username and password to the server to request an access token
     * @param \Silex\Application $app
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function userGrant(Application $app)
    {
        $session = $app['session'];         // the session (or user) object
        $twig   = $app['twig'];             // used to render twig templates
        $config = $app['parameters'];       // the configuration for the current oauth implementation
        $urlgen = $app['url_generator'];    // generates URLs based on our routing
        $curl   = new Curl();               // simple class used to make curl requests
        
        // Check the state
        if ($app['request']->get('state') !== $session->getId()) {
            return $twig->render('client/failed_token_request.twig', array('response' => array( "error_description" => "Session Expired")));
        }

        // Set endpoint for request
        $route = $config['token_route'];
        $endpoint = 0 === strpos($route, 'http') ? $route : $urlgen->generate($route, array(), true);
        
        $query = array(
            'grant_type'    => 'password',
            'username'      => $app['request']->get('username'),    // Pulling from url for example here
            'password'      => $app['request']->get('password'),
        );
        
        // Check for optional params and add to query if set
        $app['request']->get('scope') ? $query['scope'] = $app['request']->get('scope') : '';
     
        // Configure options to use the Authorization Header to pass the client_id and client_secret
        $options = array_merge(
            array(
                'auth' => true,
                'client_id'     => $config['client_id'],       //pulls from client configuration file
                'client_secret' => $config['client_secret'],
            ),
            $config['curl_options']
        );
      
        // make the token request via curl and decode the json response
        $response = $curl->request($endpoint, $query, 'POST', $options);
        $json = json_decode($response['response'], true);
            
        // Return a successful response
        if (isset($json['access_token'])) {
            return $twig->render('client/show_access_token.twig', array('token' => $json['access_token'], 'session_id' => $session->getId()));
        }
        
        // Return a failed response
        return $twig->render('client/failed_token_request.twig', array('response' => $json ? $json : $response));
    }
}
