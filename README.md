Laravel 10.x simple Google Authenticator 2FA auth support.

## Installation

Install using composer 

```sh
composer require evgen-dev/google-authenticator
```

Add the provider to `config/app.php`

```php
'providers' => [
    EvgenDev\GoogleAuthenticator\GoogleAuthenticatorServiceProvider::class,
]
```

# Using
```php
use EvgenDev\GoogleAuthenticator;

GoogleAuthenticator::getCode('YOUR_SECRET_STRING');
GoogleAuthenticator::checkCode('YOUR_SECRET_STRING', 'YOUR_CODE');
GoogleAuthenticator::getQRCodeUrl('username', 'example.org', 'YOUR_SECRET_STRING');
GoogleAuthenticator::generateSecret();
```