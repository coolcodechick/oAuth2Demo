<?php

namespace OAuth2Demo\Client\Controllers;

use OAuth2Demo\Shared\Curl;
use Silex\Application;

/**
 * Uses Authorization Code Grant Type to retrieve a code in Step 1 
 * ( see Oauth2Demo/Client/Controller/RecieveAuthorizationCode.php ) 
 * and then the token in Step 2 ( HERE )
 * Once the access_token is recieved this renders the Twig template, 
 * this can be done behind the scenes, but renders a page for demonstration purposes.
 * Should have it redirect to request resource.
 * 
 * REQUEST : HttpRequest = POST
 *           REQUIRED : client_id               *** client credntials are passed in Authorization header ***
 *                      client_secret 
 *                      grant_type = "authorization_code"
 *                      code
 *                      redirect_uri
 *           OPTIONAL : No Optional items listed in Standard Track
 *                      
 * RETURNS : Returns response and redirects with token in query string 
 *              ( ie. ?access_token=____&state=____ )
 *           REQUIRED : access_token
 *                      expires_in
 *                      token_type = "bearer"
 *                      refresh_token
 *           OPTIONAL : scope
 */
class RequestToken
{
    /**
     * Connects the routes in Silex 
     * @param type $routing
     */
    public static function addRoutes($routing)
    {
        $routing->get('/client/request_token', array(new self(), 'requestToken'))->bind('request_token');
    }

    /**
     * Requests an access token 
     * @param \Silex\Application $app
     * @return type
     */
    public function requestToken(Application $app)
    {
        $twig   = $app['twig'];             // used to render twig templates
        $config = $app['parameters'];       // the configuration for the current oauth implementation
        $urlgen = $app['url_generator'];    // generates URLs based on our routing
        $session = $app['session'];         // the session (or user) object
        $curl   = new Curl();               // simple class used to make curl requests
        
        // Check the state
        if ($app['request']->get('state') !== $session->getId()) {
            return $twig->render('client/failed_authorization.twig', array('response' => array('error_description' => 'BOOM! Your session has expired.  Please try again.')));
        }

        // Set endpoint for request
        $route = $config['token_route'];
        $endpoint = 0 === strpos($route, 'http') ? $route : $urlgen->generate($route, array(), true);
        
        // Set the grant_type and REQUIRED params
        $query = array(
                'grant_type'    => 'authorization_code',
                'code'          => $app['request']->get('code'),
                'redirect_uri'  => $urlgen->generate('authorize_redirect', array(), true),
        );
        
        $options = $config['curl_options'];
        
        // Google does not accept the client_id and client_secret in the Authorization header so...
        // Check if it is the google enviroment and add the client_id and client_secret to the query
        if ($app['session']->get('config_environment') == 'Google Tasks') {
            $query = array_merge(
                array(
                    'client_id'     => $config['client_id'],       //pulls from client configuration file
                    'client_secret' => $config['client_secret'],
                ),
                $query
            );
        } else {
            // Configure options to use the Authorization Header to pass the client_id and client_secret
            $options = array_merge(
                array(
                    'auth' => true,
                    'client_id'     => $config['client_id'],       //pulls from client configuration file
                    'client_secret' => $config['client_secret'],
                ),
                $options
            );
        }
            
        // Make the request via curl and decode the json response
        $response = $curl->request($endpoint, $query, 'POST', $options);
        $json = json_decode($response['response'], true);

        // Store the refresh_token so it can be used to renew the access token later
        if (isset($json['refresh_token'])) {
            $session->set('refresh_token', $json['refresh_token']);
        }
        
        // Return a successful response
        if (isset($json['access_token'])) {
            return $twig->render('client/show_access_token.twig', array('token' => $json['access_token'], 'session_id' => $session->getId()));
            // Instead of displaying token, use it to get the requested resource and add the  lib to this page
            //return $app->redirect($app['url_generator']->generate('request_resource', array("token" => $json["access_token"])));
        }

        // Return a failed response
        return $twig->render('client/failed_token_request.twig', array('response' => $json ? $json : $response));
    }
}
