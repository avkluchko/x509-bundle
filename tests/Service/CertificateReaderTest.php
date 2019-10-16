<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\CertificateReader;
use PHPUnit\Framework\TestCase;

class CertificateReaderTest extends TestCase
{
    private $reader;

    public function setUp(): void
    {
        $this->reader = new CertificateReader();
    }

    public function testLoadData()
    {
        // load normal x509 certificate file
        $data = $this->reader->loadData(__DIR__ . '/../example/ivanov_crypto_2001_base64.cer');

        $this->assertArrayHasKey('subject', $data);
        $this->assertArrayHasKey('issuer', $data);
        $this->assertArrayHasKey('fingerprint', $data);
    }

    public function testLoadDataDERFile()
    {
        // load certificate in DER file
        $data = $this->reader->loadData(__DIR__ . '/../example/ivanov_crypto_2001_der.cer');

        $this->assertArrayHasKey('subject', $data);
        $this->assertArrayHasKey('issuer', $data);
        $this->assertArrayHasKey('fingerprint', $data);
    }
}