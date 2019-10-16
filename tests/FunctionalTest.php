<?php

namespace AVKluchko\X509Bundle\Tests;

use AVKluchko\X509Bundle\Service\CertificateReader;
use AVKluchko\X509Bundle\Service\Parser;
use AVKluchko\X509Bundle\X509Bundle;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Config\Loader\LoaderInterface;
use Symfony\Component\HttpKernel\Kernel;

class FunctionalTest extends TestCase
{
    public function testServiceWiring()
    {
        $kernel = new X509TestingKernel();
        $kernel->boot();
        $container = $kernel->getContainer();

        $reader = $container->get('avkluchko_x509.certificate_reader');
        $this->assertInstanceOf(CertificateReader::class, $reader);

        $parser = $container->get('avkluchko_x509.parser');
        $this->assertInstanceOf(Parser::class, $parser);
    }
}

class X509TestingKernel extends Kernel
{
    public function __construct()
    {
        parent::__construct('test', true);
    }

    public function registerBundles()
    {
        return [
            new X509Bundle(),
        ];
    }

    public function registerContainerConfiguration(LoaderInterface $loader)
    {
    }

    public function getCacheDir()
    {
        return __DIR__ . '/cache/' . spl_object_hash($this);
    }
}