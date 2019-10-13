<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\CertificateReader;
use PHPUnit\Framework\TestCase;

class CertificateReaderTest extends TestCase
{
    public function testReadCertificate()
    {
        $reader = new CertificateReader();

        $data = $reader->readData(__DIR__ . '/../../temp/FSS_TEST_CERT_2020.cer');
        var_dump($data);

        $this->assertEquals(42,42);
    }
}