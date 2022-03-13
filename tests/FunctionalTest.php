<?php

namespace AVKluchko\X509Bundle\Tests;

use AVKluchko\X509Bundle\Service\CertificateReader;
use AVKluchko\X509Bundle\Service\Parser;
use PHPUnit\Framework\TestCase;

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
