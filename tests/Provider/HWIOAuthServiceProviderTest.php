<?php

namespace Sergiors\Silex\Tests\Provider;

use Silex\Application;
use Silex\WebTestCase;

class HWIOAuthServiceProviderTest extends WebTestCase
{
    public function createApplication()
    {
        $app = new Application();
        $app['debug'] = true;
        return $app;
    }
}