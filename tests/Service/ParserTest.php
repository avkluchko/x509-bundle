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

    public function testParse()
    {
        $parsedData = $this->parser->parse(__DIR__ . '/../example/ivanov_crypto_2001_base64.cer');
//        $parsedData = $this->parser->parse(__DIR__ . '/../temp/official2.cer');

        $this->assertIsArray($parsedData['data']);
        $this->assertNotEmpty($parsedData['fingerprint']);
        $this->assertArrayHasKey('signTool', $parsedData);
        $this->assertArrayHasKey('commonName', $parsedData['issuer']);
        $this->assertArrayHasKey('name', $parsedData['issuer']);
        $this->assertArrayHasKey('unitName', $parsedData['issuer']);
        $this->assertArrayHasKey('country', $parsedData['issuer']);
        $this->assertArrayHasKey('state', $parsedData['issuer']);
        $this->assertArrayHasKey('locality', $parsedData['issuer']);
        $this->assertArrayHasKey('address', $parsedData['issuer']);
        $this->assertArrayHasKey('email', $parsedData['issuer']);
        $this->assertArrayHasKey('PSRN', $parsedData['issuer']);
        $this->assertArrayHasKey('TIN', $parsedData['issuer']);

    }
}