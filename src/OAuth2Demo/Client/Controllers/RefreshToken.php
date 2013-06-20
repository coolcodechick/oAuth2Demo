<?php

namespace OAuth2Demo\Client\Controllers;

use OAuth2Demo\Shared\Curl;
use Silex\Application;

/**
 * Makes a request for a new access token by using the refresh token.
 * 
 * REQUEST : HttpRequest = GET
 *           REQUIRED : client_id               *** client credentials are passed in Authorization header ***
 *                      client_secret 
 *                      grant_type = "refresh_token"
 *                      refresh_token
 *           OPTIONAL : scope
 *                      
 * RETURNS : Returns response and redirects with token in query string
 *              ( ie. ?access_token=____&state=____ )
 *           REQUIRED : access_token
 *                      expires_in              *** Default 3600 ***
 *                      token_type = "bearer"
 *           OPTIONAL : scope
 *                      refresh_token           
 *                          *** by default refersh_token is not reissued but 
 *                              can configure 'always_issue_new_refresh_token' to true 
 *                              ( see OAuth2Demo/Server/Server.php ~ line 42 ) ***
 * @author tanya brodsky
 */
class RefreshToken
{
    /**
     * Uses a refresh token to get a new access token.
     * @param \Silex\Application $app
     * @return json Returns the response in json format
     */
    public static function requestRefreshToken(Application $app)
    {
        $config = $app['parameters'];       // the configuration for the current oauth implementation
        $urlgen = $app['url_generator'];    // generates URLs based on our routing
        $session = $app['session'];         // the session (or user) object
        $curl   = new Curl();               // simple class used to make curl requests

        // Check the state
        if ($app['request']->get('state') !== $session->getId()) {
            return $twig->render('client/failed_token_request.twig', array('response' => array( "error_description" => "Session Expired")));
        }
        
        // Set endpoint for request
        $route = $config['token_route'];
        $endpoint = 0 === strpos($route, 'http') ? $route : $urlgen->generate($route, array(), true);
        
        // Set the grant_type and REQUIRED params
        $query = array(
            'grant_type'    => 'refresh_token',
            'refresh_token' => $session->get('refresh_token'),
        );
        
        // Check for OPTIONAL params and add to query array if set
        $app['request']->get('scope') ? $query['scope'] = $app['request']->get('scope') : '';
        
        // Configure options to use the Authorization Header to pass the client_id and client_secret
        $options = array_merge(
            array(
                'auth' => true,
                'client_id'     => $config['client_id'],        //pulls from client configuration file
                'client_secret' => $config['client_secret'],
            ),
            $config['curl_options']
        );
        
        // make the token request via curl and decode the json response
        $response = $curl->request($endpoint, $query, 'POST', $options);
        $json = json_decode($response['response'], true);

        // If a ne refresh_token was issued store it
        if (isset($json['refresh_token'])) {
            $session->set('refresh_token', $json['refresh_token']);
        }
        
        // Return the response
        return $json ? $json : $response;
    }
}
