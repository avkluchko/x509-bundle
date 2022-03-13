<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\CertificateReader;
use PHPUnit\Framework\TestCase;

class CertificateReaderTest extends TestCase
{
    private CertificateReader $reader;

    public function setUp(): void
    {
        $this->reader = new CertificateReader();
    }

    public function testLoadData(): void
    {
        // load normal x509 certificate file
        $data = $this->reader->loadData(__DIR__ . '/../example/ivanov_crypto_2001_base64.cer');

        self::assertArrayHasKey('subject', $data);
        self::assertArrayHasKey('issuer', $data);
        self::assertArrayHasKey('fingerprint', $data);
    }

    public function testLoadDataDERFile(): void
    {
        // load certificate in DER file
        $data = $this->reader->loadData(__DIR__ . '/../example/ivanov_crypto_2001_der.cer');

        self::assertArrayHasKey('subject', $data);
        self::assertArrayHasKey('issuer', $data);
        self::assertArrayHasKey('fingerprint', $data);
    }
}
