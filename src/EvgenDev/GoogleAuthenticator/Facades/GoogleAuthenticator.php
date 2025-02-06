<?php

namespace EvgenDev\GoogleAuthenticator\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @see \EvgenDev\GoogleAuthenticator\Manager
 */
class GoogleAuthenticator extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'googleauthenticator';
    }
}