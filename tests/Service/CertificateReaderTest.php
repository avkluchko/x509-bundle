<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\CertificateReader;
use PHPUnit\Framework\TestCase;

class CertificateReaderTest extends TestCase
{
    public function testReadCertificate()
    {
        $reader = new CertificateReader();

        $data = $reader->loadData(__DIR__ . '/../example/ivanov_crypto_2001_der.cer');

        $this->assertArrayHasKey('subject', $data);
        $this->assertArrayHasKey('issuer', $data);
        $this->assertArrayHasKey('fingerprint', $data);

        $data = $reader->loadData(__DIR__ . '/../example/ivanov_crypto_2001_base64.cer');

        $this->assertArrayHasKey('subject', $data);
        $this->assertArrayHasKey('issuer', $data);
        $this->assertArrayHasKey('fingerprint', $data);
    }


}