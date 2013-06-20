<?php

namespace OAuth2Demo\Client\Controllers;

use OAuth2Demo\Shared\Curl;
use Silex\Application;

/**
 * Uses Authorization Code Grant Type to retrieve a code in Step 1 ( HERE ) and then 
 * the token in Step 2 ( see Oauth2Demo/Client/Controller/RequestToken.php )
 * Controller used once the Authorization code is recieved and renders the Twig template, 
 * usually this is done behind the scenes, but renders a page for demonstration purposes.
 * Should have it redirect to request token.
 * 
 * REQUEST : HttpRequest = GET
 *           REQUIRED : response_type = "code"
 *                      client_id       
 *           OPTIONAL : redirect_uri
 *                      scope
 *                      state
 *                      
 * RETURNS : Returns response and Redirects with code in the url query string 
 *              ( ie. ?code=b25019484a04cd41ea8bbbfaec6cf58ded1702ee&state=dddfaab765dc49511c1a99103565d979 )
 *           REQUIRED : code            *** recommended to expire in 10 minutes ***
 *           OPTIONAL : state
 */
class ReceiveAuthorizationCode
{
    /**
     * Connects the routes in Silex 
     * @param type $routing
     */
    public static function addRoutes($routing)
    {
        $routing->get('/client/receive_authcode', array(new self(), 'receiveAuthorizationCode'))->bind('authorize_redirect');
    }

    /**
     * Redirects to request token once authorization code is retrieved
     * @param \Silex\Application $app
     * @return type
     */
    public function receiveAuthorizationCode(Application $app)
    {
        $request = $app['request']; // the request object
        $session = $app['session']; // the session (or user) object
        $twig    = $app['twig'];    // used to render twig templates

        // Check the state
        if ($request->get('state') !== $session->getId()) {
            return $twig->render('client/failed_authorization.twig', array('response' => array('error_description' => 'Your session has expired.  Please try again.')));
        }
        
        // Check if user denied the authorization request
        if (!$code = $request->get('code')) {
            return $twig->render('client/failed_authorization.twig', array('response' => $request->getAllQueryParameters()));
        }
        
            // Can show Authorization Code
            //return $twig->render('client/show_authorization_code.twig', array('code' => $code, 'session_id' => $session->getId()));
        // Redirect directly to the request_token without user interaction
        return $app->redirect($app['url_generator']->generate('request_token', array("code" => $code, "state" => $request->get('state'))));
    }
}
