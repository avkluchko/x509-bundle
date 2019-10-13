<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\CertificateReader;
use PHPUnit\Framework\TestCase;

class CertificateReaderTest extends TestCase
{
    public function testReadCertificate()
    {
        $certificateReader = new CertificateReader(__DIR__ . '/../../temp/FSS_TEST_CERT_2020.cer');

        var_dump($certificateReader->getData());

        $this->assertEquals(42,42);
    }
}