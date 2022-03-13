# X509 Bundle

[![Build Status](https://travis-ci.org/avkluchko/x509-bundle.svg)](https://travis-ci.org/avkluchko/x509-bundle)
[![Total Downloads](https://poser.pugx.org/avkluchko/x509-bundle/downloads)](https://packagist.org/packages/avkluchko/x509-bundle)
[![Latest Stable Version](https://poser.pugx.org/avkluchko/x509-bundle/v/stable)](https://packagist.org/packages/avkluchko/x509-bundle)
[![License](https://poser.pugx.org/avkluchko/x509-bundle/license)](https://packagist.org/packages/avkluchko/x509-bundle)

Services for work with x509 certificate.

## Requirements

The minumum requirement by X509 Bundle is that your web-server supports PHP 8.0 or above. 

**Warning!** Need installed openssl php extension.

## Installation

Install the package with:

```console
composer require avkluchko/x509-bundle
```

If you're *not* using Symfony Flex, you'll also
need to enable the `AVKluchko\X509Bundle\X509Bundle`
in your `AppKernel.php` file.

## Usage

```php
// src/Controller/SomeController.php
use AVKluchko\X509Bundle\Service\Parser;

// ...
class SomeController
{
    public function index(Parser $parser)
    {
        $data = $parser->parse('some_certificate_file');
        // ...
    }
}
```
