<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\CertificateReader;
use AVKluchko\X509Bundle\Service\Parser;
use PHPUnit\Framework\TestCase;

class ParserTest extends TestCase
{
    private $parser;

    protected function setUp(): void
    {
        $this->parser = new Parser(new CertificateReader());
    }

    /**
     * @dataProvider getCertificatePaths
     */
    public function testParse(string $path)
    {
        $data = $this->parser->parse(__DIR__ . $path);

        $this->assertIsArray($data['data']);
        $this->assertNotEmpty($data['fingerprint']);
        $this->assertArrayHasKey('signTool', $data);
        $this->assertArrayHasKey('extendedKeyUsage', $data);

        $this->assertNotNull($data['validPeriod']['from']);
        $this->assertNotNull($data['validPeriod']['to']);
        $this->assertArrayHasKey('privateKeyUsagePeriod', $data);

        // asserts subject
        $this->assertArrayHasKey('type', $data['subject']);
        $this->assertArrayHasKey('shortName', $data['subject']);
        $this->assertArrayHasKey('company', $data['subject']);
        $this->assertArrayHasKey('title', $data['subject']);
        $this->assertArrayHasKey('country', $data['subject']);
        $this->assertArrayHasKey('state', $data['subject']);
        $this->assertArrayHasKey('locality', $data['subject']);
        $this->assertArrayHasKey('address', $data['subject']);
        $this->assertArrayHasKey('email', $data['subject']);
        $this->assertArrayHasKey('OGRN', $data['subject']);
        $this->assertArrayHasKey('INN', $data['subject']);
        $this->assertArrayHasKey('surname', $data['subject']);
        $this->assertArrayHasKey('name', $data['subject']);
        $this->assertArrayHasKey('middleName', $data['subject']);
        $this->assertArrayHasKey('SNILS', $data['subject']);

        // asserts issuer
        $this->assertArrayHasKey('name', $data['issuer']);
        $this->assertArrayHasKey('shortName', $data['issuer']);
        $this->assertArrayHasKey('unitName', $data['issuer']);
        $this->assertArrayHasKey('country', $data['issuer']);
        $this->assertArrayHasKey('state', $data['issuer']);
        $this->assertArrayHasKey('locality', $data['issuer']);
        $this->assertArrayHasKey('address', $data['issuer']);
        $this->assertArrayHasKey('email', $data['issuer']);
        $this->assertArrayHasKey('OGRN', $data['issuer']);
        $this->assertArrayHasKey('INN', $data['issuer']);
    }

    public function getCertificatePaths()
    {
        return [
            ['/../example/ivanov_crypto_2001_base64.cer'],
            ['/../example/ivanov_crypto_2001_der.cer'],
            ['/../temp/official1.cer'],
            ['/../temp/official2.cer'],
            ['/../temp/person1.cer'],
            ['/../temp/person2.cer'],
            ['/../temp/company.cer'],
        ];
    }
}