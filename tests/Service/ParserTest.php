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
        $parsedData = $this->parser->parse(__DIR__ . $path);

        $this->assertIsArray($parsedData['data']);
        $this->assertNotEmpty($parsedData['fingerprint']);
        $this->assertArrayHasKey('signTool', $parsedData);

        // asserts subject
        $this->assertArrayHasKey('type', $parsedData['subject']);
        $this->assertArrayHasKey('shortName', $parsedData['subject']);
        $this->assertArrayHasKey('company', $parsedData['subject']);
        $this->assertArrayHasKey('title', $parsedData['subject']);
        $this->assertArrayHasKey('country', $parsedData['subject']);
        $this->assertArrayHasKey('state', $parsedData['subject']);
        $this->assertArrayHasKey('locality', $parsedData['subject']);
        $this->assertArrayHasKey('address', $parsedData['subject']);
        $this->assertArrayHasKey('email', $parsedData['subject']);
        $this->assertArrayHasKey('OGRN', $parsedData['subject']);
        $this->assertArrayHasKey('INN', $parsedData['subject']);
        $this->assertArrayHasKey('surname', $parsedData['subject']);
        $this->assertArrayHasKey('name', $parsedData['subject']);
        $this->assertArrayHasKey('middleName', $parsedData['subject']);
        $this->assertArrayHasKey('SNILS', $parsedData['subject']);

        // asserts issuer
        $this->assertArrayHasKey('name', $parsedData['issuer']);
        $this->assertArrayHasKey('shortName', $parsedData['issuer']);
        $this->assertArrayHasKey('unitName', $parsedData['issuer']);
        $this->assertArrayHasKey('country', $parsedData['issuer']);
        $this->assertArrayHasKey('state', $parsedData['issuer']);
        $this->assertArrayHasKey('locality', $parsedData['issuer']);
        $this->assertArrayHasKey('address', $parsedData['issuer']);
        $this->assertArrayHasKey('email', $parsedData['issuer']);
        $this->assertArrayHasKey('OGRN', $parsedData['issuer']);
        $this->assertArrayHasKey('INN', $parsedData['issuer']);

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