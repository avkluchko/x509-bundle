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

//    /**
//     * @dataProvider getCertificatePaths
//     *
//     * @param string $path
//     */
//    public function testLoadData_Values(string $path): void
//    {
//        $data = $this->reader->loadData(__DIR__ . $path);
//
//        var_dump($data['undefined']);
//
//        self::assertNotNull($data);
//    }
//
//    public function getCertificatePaths(): array
//    {
//        return [
//            ['/../example/ivanov_crypto_2001_base64.cer'],
//            ['/../example/ivanov_crypto_2001_der.cer'],
//            ['/../temp/official1.cer'],
//            ['/../temp/official2.cer'],
//            ['/../temp/person1.cer'],
//            ['/../temp/person2.cer'],
//            ['/../temp/person3.cer'],
//            ['/../temp/company.cer'],
//            ['/../temp/company2.cer'],
//        ];
//    }
}