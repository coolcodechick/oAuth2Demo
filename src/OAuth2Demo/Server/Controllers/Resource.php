<?php

namespace OAuth2Demo\Server\Controllers;

use Silex\Application;
use Symfony\Component\HttpFoundation\Response;

class Resource
{
    /**
     * Connects the routes in Silex
     * @param type $routing
     */
    public static function addRoutes($routing)
    {
        $routing->get('/apiResource', array(new self(), 'resource'))->bind('access');
    }
    
    /**
     * This is called by the client app once the client has obtained an access
     * token for the current user.  If the token is valid, the resources requested will be called
     * it will verify the request ant the scope required and build the response
     * and the response will be returned to the client.
     * @param \Silex\Application $app
     * @return \Symfony\Component\HttpFoundation\Response
     */
    public function resource(Application $app)
    {
        $include = $app['request']->get('include');
        
        $server = $app['oauth_server'];
        
        if (!$server->verifyResourceRequest($app['request'])) {
            return $server->getResponse();
        } else {
            // return a fake API response - not that exciting
            // @TODO return something more valuable, like the name of the logged in user
            // Returns default api company info to display in footer does not have a scope requirement
            $api_response = array(
                'info' => array (
                    'organization' => 'My Demo Application',
                    'website'  => 'www.mydemoapp.com',
                ),
                'contact' => array(
                    'mailing_address'   => '123 Test Address Street Sunshine, FL 33913',
                    'email'             => 'info@mydemoapp.com'
                )
            );
      
            // Check which includes are included, verify the token has access to the scope,
            // get those resources, and merge to api_response
            if (strstr($include, 'basic')) {
                $scopeRequired = 'basic'; // this resource requires "friends" scope
                if (!$server->verifyResourceRequest($app['request'], $scopeRequired)) {
                    // if the scope required is different from what the token allows,
                    // this will send a "401 insufficient_scope" error
                    return $server->getResponse();
                } else {
                        $basic_profile = $this->getBasicInformation();
                        $api_response = array_merge($api_response, $basic_profile);
                }
            }
            if (strstr($include, 'profile')) {
                $scopeRequired = 'profile';             // this resource requires "profile" scope
        
                if (!$server->verifyResourceRequest($app['request'], $scopeRequired)) {
                    return $server->getResponse();
                } else {
                    $profile = $this->getFullProfile();
                    $api_response = array_merge($api_response, $profile);
                }
            }
            if (strstr($include, 'friends')) {
                $scopeRequired = 'friends'; // this resource requires "friends" scope
                if (!$server->verifyResourceRequest($app['request'], $scopeRequired)) {
                    return $server->getResponse();
                } else {
                    $friends = $this->getFriendsDetails();
                    $api_response = array_merge($api_response, $friends);
                }
            }
            return new Response(json_encode($api_response));
        }
    }

    /**
     * Gets the requested resource
     * @TODO Return something more valuable like pull from the database versus this static information
     * @param \Silex\Application $app
     * @return array
     */
    public function getBasicInformation()
    {
        $api_response = array(
            'profile' => array (
                'firstName' => 'Tanya',
                'lastName'  => 'Brodsky',
                'location'  => 'Orlando, FL',
                'astro_sign' => 'Taurus',
                'quote' => 'Something thoughtful here.',
            ),
            'friends' => array(
                array(
                    'firstName' => 'johnny'
                ),
                array(
                    'firstName' => 'matthew'
                ),
                array(
                    'firstName' => 'jane'
                )
            )
        );
        return $api_response;
    }
    
    /**
     * Gets the requested resource 
     * @TODO Return something more valuable like pull from the database versus this static information
     * @param \Silex\Application $app
     * @return array
     */
    public function getFullProfile()
    {
        $api_response = array(
            'profile' => array (
                'firstName' => 'Tanya',
                'lastName'  => 'Brodsky',
                'location'  => 'Orlando, FL',
                'astro_sign' => 'Taurus',
                'quote' => 'Something thoughtful here.',
                'details'   => array(
                    'email'     => 'tanya@coolcodechick.com',
                    'dob'       => '05/07/1984',
                    'phone'     => '239-244-1234'
                 )
            ),
        );
        return $api_response;
    }
    
    /**
     * Gets the requested resource
     * @TODO Return something more valuable like pull from the database versus this static information
     * @param \Silex\Application $app
     * @return array
     */
    public function getFriendsDetails()
    {
        $api_response = array(
            'friends' => array(
                array(
                    'firstName' => 'johnny',
                    'lastName' => 'bravo',
                    'email' => 'jonny@gmail.com',
                    'dob' => '12/04/1982'
                ),
                array(
                    'firstName' => 'matthew',
                    'lastName' => 'wehttam',
                    'email' => 'matt@gmail.com',
                    'dob' => '09/21/1984'
                ),
                array(
                    'firstName' => 'jane',
                    'lastName' => 'doe',
                    'email' => 'jane@gmail.com',
                    'dob' => '02/14/1983'
                )
            )
        );
        return $api_response;
    }
}
