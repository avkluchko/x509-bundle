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

        $this->assertIsArray($parsedData['data']);
        $this->assertNotEmpty($parsedData['fingerprint']);
        $this->assertNull($parsedData['signTool']);
        $this->assertArrayHasKey('name', $parsedData['issuer']);
        $this->assertArrayHasKey('shortName', $parsedData['issuer']);
        $this->assertArrayHasKey('PSRN', $parsedData['issuer']);
    }
}