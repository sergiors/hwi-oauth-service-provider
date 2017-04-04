<?php

namespace Sergiors\Silex\Provider;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Application;
use Silex\Api\BootableProviderInterface;
use Silex\Api\ControllerProviderInterface;
use HWI\Bundle\OAuthBundle\Security\Http\Firewall\OAuthListener;
use HWI\Bundle\OAuthBundle\Security\Http\EntryPoint\OAuthEntryPoint;
use HWI\Bundle\OAuthBundle\Security\OAuthUtils;
use HWI\Bundle\OAuthBundle\Security\Core\Authentication\Provider\OAuthProvider;
use HWI\Bundle\OAuthBundle\Security\Core\User\OAuthUserProvider;
use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\FacebookResourceOwner;
use HWI\Bundle\OAuthBundle\OAuth\ResourceOwner\GoogleResourceOwner;
use HWI\Bundle\OAuthBundle\OAuth\RequestDataStorage\SessionStorage;
use HWI\Bundle\OAuthBundle\Templating\Helper\OAuthHelper;
use HWI\Bundle\OAuthBundle\Twig\Extension\OAuthExtension;
use Sergiors\Silex\Security\Http\ResourceOwnerMap;
use Sergiors\Silex\Controller\ConnectController;

/**
 * @author Sérgio Rafael Siqueira <sergio@inbep.com.br>
 */
final class HWIOAuthServiceProvider implements
    ServiceProviderInterface,
    ControllerProviderInterface,
    BootableProviderInterface
{
    private $fakeRoutes = [];

    public function register(Container $app)
    {
        $that = $this;

        $app['security.authentication_listener.factory.oauth'] = $app->protect(function ($name, $options) use ($app) {
            if (!isset($app['security.authentication_provider.'.$name.'.oauth'])) {
                $app['security.authentication_provider.'.$name.'.oauth'] = $app['hwi_oauth.authentication.provider.oauth._proto']($name, $options);
            }

            if (!isset($app['security.authentication_listener.'.$name.'.oauth'])) {
                $app['security.authentication_listener.'.$name.'.oauth'] = $app['hwi_oauth.authentication.listener.oauth._proto']($name, $options);
            }

            if (!isset($app['security.entry_point.'.$name.'.oauth'])) {
                $app['security.entry_point.'.$name.'.oauth'] = $app['hwi_oauth.entry_point.oauth._proto']($name, $options);
            }

            return [
                'security.authentication_provider.'.$name.'.oauth',
                'security.authentication_listener.'.$name.'.oauth',
                'security.entry_point.'.$name.'.oauth',
                'http'
            ];
        });

        $app['hwi_oauth.user.provider'] = function () {
            return new OAuthUserProvider();
        };

        $app['hwi_oauth.authentication.listener.oauth._proto'] = $app->protect(function ($name, array $options) use ($app, $that) {
            return function () use ($app, $name, $options, $that) {
                if (!isset($app['security.authentication.success_handler.'.$name])) {
                    $app['security.authentication.success_handler.'.$name] = $app['security.authentication.success_handler._proto']($name, $options);
                }

                if (!isset($app['security.authentication.failure_handler.'.$name])) {
                    $app['security.authentication.failure_handler.'.$name] = $app['security.authentication.failure_handler._proto']($name, $options);
                }

                $checkPaths = array_reduce(
                    $resourceOwners = isset($options['resource_owners']) ? $options['resource_owners'] : [],
                    function (array $checkPaths, $path) use ($that, $resourceOwners) {
                        $name = array_search($path, $resourceOwners);
                        $that->addFakeRoute('get', $path, $name);

                        return array_merge($checkPaths, [$path]);
                    }, []
                );

                $listener = new OAuthListener(
                    $app['security.token_storage'],
                    $app['security.authentication_manager'],
                    isset($app['security.session_strategy.'.$name]) ? $app['security.session_strategy.'.$name] : $app['security.session_strategy'],
                    $app['security.http_utils'],
                    $name,
                    $app['security.authentication.success_handler.'.$name],
                    $app['security.authentication.failure_handler.'.$name],
                    $options,
                    $app['logger'],
                    $app['dispatcher']
                );

                $listener->setResourceOwnerMap($app['hwi_oauth.abstract_resource_ownermap']);
                $listener->setCheckPaths($checkPaths);

                return $listener;
            };
        });

        $app['hwi_oauth.authentication.provider.oauth._proto'] = $app->protect(function ($name, array $options) use ($app) {
            return function () use ($app, $name, $options) {
                return new OAuthProvider(
                    $app['hwi_oauth.user.provider'],
                    $app['hwi_oauth.abstract_resource_ownermap'],
                    $app['security.user_checker']
                );
            };
        });

        $app['hwi_oauth.entry_point.oauth._proto'] = $app->protect(function ($name, array $options) use ($app) {
            return function () use ($app, $name, $options) {
                $loginPath = isset($options['login_path']) ? $options['login_path'] : '/login';
                $useForward = isset($options['use_forward']) ? $options['use_forward'] : false;

                return new OAuthEntryPoint($app, $app['security.http_utils'], $loginPath, $useForward);
            };
        });

        $app['hwi_oauth.storage.session'] = function (Container $app) {
            return new SessionStorage($app['session']);
        };

        $app['hwi_oauth.security.oauth_utils'] = function (Container $app) {
            $utils = new OAuthUtils(
                $app['security.http_utils'],
                $app['security.authorization_checker'],
                $app['hwi_oauth.connect'],
                $app['hwi_oauth.grant_rule']
            );

            $utils->addResourceOwnerMap($app['hwi_oauth.abstract_resource_ownermap']);

            return $utils;
        };

        $app['hwi_oauth.abstract_resource_ownermap'] = function (Container $app) use ($that) {
            foreach ($app['hwi_oauth.resource_owners'] as $options) {
                $type = $options['type'];

                if (!isset($app['hwi_oauth.resource_owner.'.$type])) {
                    $app['hwi_oauth.resource_owner.'.$type] = $app['hwi_oauth.resource_owner.'.$type.'._proto']($type, array_diff($options, [$type]));
                }
            };

            $possibleResourceOwners = ['facebook' => true, 'google' => true];
            $resourceOwners = array_reduce($app['hwi_oauth.firewall_names'], function (array $resourceOwners, $name) use ($app) {
                if (isset($app['security.firewalls'][$name]['oauth']['resource_owners'])) {
                    return array_merge(
                        $resourceOwners,
                        $app['security.firewalls'][$name]['oauth']['resource_owners']
                    );
                }

                return $resourceOwners;
            }, []);

            return new ResourceOwnerMap($app, $app['security.http_utils'], $possibleResourceOwners, $resourceOwners);
        };

        $app['hwi_oauth.resource_owner.facebook._proto'] = $app->protect(function ($name, array $options) use ($app) {
            return new FacebookResourceOwner(
                $app['hwi_oauth.http_client'],
                $app['security.http_utils'],
                $options,
                $name,
                $app['hwi_oauth.storage.session']
            );
        });

        $app['hwi_oauth.resource_owner.google._proto'] = $app->protect(function ($name, array $options) use ($app) {
            return new GoogleResourceOwner(
                $app['hwi_oauth.http_client'],
                $app['security.http_utils'],
                $options,
                $name,
                $app['hwi_oauth.storage.session']
            );
        });

        $app['hwi_oauth.templating.helper.oauth'] = function (Container $app) {
            return new OAuthHelper($app['hwi_oauth.security.oauth_utils'], $app['request_stack']);
        };

        $app['hwi_oauth_service_redirect'] = function () {
            return new ConnectController();
        };

        $app['hwi_oauth.http_client'] = function () {
            return new \Buzz\Client\Curl();
        };

        $app['hwi_oauth.firewall_names'] = function (Container $app) {
            return array_keys(
                array_filter($app['security.firewalls'], function (array $firewall) {
                    return isset($firewall['oauth']);
                })
            );
        };

        $app['twig'] = $app->extend('twig', function (\Twig_Environment $twig) use ($app) {
            $twig->addExtension(new OAuthExtension($app['hwi_oauth.templating.helper.oauth']));
            return $twig;
        });

        $app['hwi_oauth.connect'] = false;
        $app['hwi_oauth.grant_rule'] = 'IS_AUTHENTICATED_REMEMBERED';
        $app['hwi_oauth.target_path_parameter'] = null;
        $app['hwi_oauth.use_referer'] = true;
        $app['hwi_oauth.resource_owners'] = [];
    }

    public function boot(Application $app)
    {
        $app->mount('/', $this->connect($app));
    }

    public function connect(Application $app)
    {
        $controllers = $app['controllers_factory'];
        $controllers->get('/{service}', 'hwi_oauth_service_redirect:redirectToServiceAction')->bind('hwi_oauth_service_redirect');

        foreach ($this->fakeRoutes as $route) {
            list($method, $pattern, $name) = $route;
            $controllers->$method($pattern)->run(null)->bind($name);
        }

        return $controllers;
    }

    public function addFakeRoute($method, $pattern, $name)
    {
        $this->fakeRoutes[] = [$method, $pattern, $name];
    }
}