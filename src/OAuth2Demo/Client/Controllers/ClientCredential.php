<?php

namespace OAuth2Demo\Client\Controllers;

use Silex\Application;
use OAuth2Demo\Shared\Curl;

/**
 * Uses an Client Credential Grant Type uses the Client Credentials for an Access Token directly. 
 *
 * REQUEST : HttpRequest = POST
 *           REQUIRED : client_id               *** client credntials are passed in Authorization header ***
 *                      client_secret 
 *                      grant_type = "client_credentials" 
 *           OPTIONAL : scope
 *                      
 * RETURNS : Returns response and redirects with token in query string (ie. ?access_token=____&state=____ )
 *           REQUIRED : access_token
 *                      expires_in              *** Default 3600 ***
 *                      token_type = "bearer"
 *           refresh_token SHOULD NOT be issued
 * 
 * @author tanya brodsky
 */
class ClientCredential
{
    
    /**
     * Connects the routes in Silex
     * @param type $routing
     */
    public static function addRoutes($routing)
    {
        //per documentation should be a get request not a post but this breaks the classes
        $routing->get('/client_grant', array(new self(), 'clientGrant'))->bind('client_grant');
    }
    
    /**
     * This is called by the client app without needing an authorization code from the Authorize Controller 
     * (@see OAuth2Demo\Server\Controllers\Authorize).
     * requires the client id and the client secret to be used to authenticate and recieve a token.
     * If the request is valid, an access token will be returned 
     * @param \Silex\Application $app
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function clientGrant(Application $app)
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
        $route = $config['client_grant'];
        $endpoint = 0 === strpos($route, 'http') ? $route : $urlgen->generate($route, array(), true);
        
        // Set the grant_type in the query
        $query['grant_type'] = 'client_credentials';

        // Check for OPTIONAL params and add to query array if set
        $app['request']->get('scope') ? $query['scope'] = $app['request']->get('scope') : '';
        $app['request']->get('redirect_uri') ? $query['redirect_uri'] = $app['request']->get('redirect_uri') : '';
        
        // Configure options to use the Authorization Header to pass the client_id and client_secret
        $options = array_merge(
            array(
                'auth' => true,
                'client_id'     => $config['client_id'],
                'client_secret' => $config['client_secret'],
            ),
            $config['curl_options']
        );

        // Send the request via curl and decode the json response
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
