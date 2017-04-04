<?php

namespace Sergiors\Silex\Controller;

use Silex\Application;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * @author Sérgio Rafael Siqueira <sergio@inbep.com.br>
 */
class ConnectController
{
    /**
     * @param Application $app
     * @param Request     $request
     * @param string      $service
     *
     * @return RedirectResponse
     */
    public function redirectToServiceAction(Application $app, Request $request, $service)
    {
        $authorizationUrl = $app['hwi_oauth.security.oauth_utils']->getAuthorizationUrl($request, $service);

        // Check for a return path and store it before redirect
        if ($request->hasSession()) {
            // initialize the session for preventing SessionUnavailableException
            $session = $request->getSession();
            $session->start();

            foreach ($app['hwi_oauth.firewall_names'] as $providerKey) {
                $sessionKey = '_security.'.$providerKey.'.target_path';

                $param = $app['hwi_oauth.target_path_parameter'];
                if (!empty($param) && $targetUrl = $request->get($param)) {
                    $session->set($sessionKey, $targetUrl);
                }

                if ($app['hwi_oauth.use_referer']
                    && !$session->has($sessionKey)
                    && ($targetUrl = $request->headers->get('Referer'))
                    && $targetUrl !== $authorizationUrl
                ) {
                    $session->set($sessionKey, $targetUrl);
                }
            }
        }

        return RedirectResponse::create($authorizationUrl)->sendHeaders();
    }
}