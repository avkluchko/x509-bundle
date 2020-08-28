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

    public function testPrivateKeyUsagePeriod(): void
    {
        self::assertNull($this->parser->parsePrivateKeyUsagePeriod([]));

        $result = $this->parser->parsePrivateKeyUsagePeriod([
            'privateKeyUsagePeriod' => 'Not Before: Jun 10 06:27:34 2019 GMT, Not After: Jun 10 06:05:54 2020 GMT'
        ]);

        self::assertEquals('2019-06-10 11:27:34', $result['from']->format('Y-m-d H:i:s'));
        self::assertEquals('2020-06-10 11:05:54', $result['to']->format('Y-m-d H:i:s'));

        $result = $this->parser->parsePrivateKeyUsagePeriod([
            'privateKeyUsagePeriod' => 'Not Before: May 28 09:25:22 2020 GMT, Not After: Aug 28 09:25:22 2021 GMT'
        ]);

        self::assertEquals('2020-05-28 14:25:22', $result['from']->format('Y-m-d H:i:s'));
        self::assertEquals('2021-08-28 14:25:22', $result['to']->format('Y-m-d H:i:s'));
    }

    public function testParseSignTool(): void
    {
        self::assertNull($this->parser->parseSignTool([]));

        self::assertEquals('"КриптоПро CSP" (версия 4.0)', $this->parser->parseSignTool([
            'subjectSignTool' => '
                       "КриптоПро CSP" (версия 4.0)'
        ]));

        self::assertEquals('"КриптоПро CSP"', $this->parser->parseSignTool([
            '1.2.643.100.111' => '
                                 "КриптоПро CSP"'
        ]));
    }

    /**
     * @dataProvider getCertificatePaths
     *
     * @param string $path
     */
    public function testParse_MustReturnAllData(string $path): void
    {
        $data = $this->parser->parse(__DIR__ . $path);

        self::assertIsArray($data['data']);
        self::assertNotEmpty($data['fingerprint']);
        self::assertArrayHasKey('signTool', $data);
        self::assertArrayHasKey('extendedKeyUsage', $data);

        self::assertNotNull($data['validPeriod']['from']);
        self::assertNotNull($data['validPeriod']['to']);
        self::assertArrayHasKey('privateKeyUsagePeriod', $data);

        // asserts subject
        self::assertArrayHasKey('type', $data['subject']);
        self::assertArrayHasKey('shortName', $data['subject']);
        self::assertArrayHasKey('company', $data['subject']);
        self::assertArrayHasKey('title', $data['subject']);
        self::assertArrayHasKey('country', $data['subject']);
        self::assertArrayHasKey('state', $data['subject']);
        self::assertArrayHasKey('locality', $data['subject']);
        self::assertArrayHasKey('address', $data['subject']);
        self::assertArrayHasKey('email', $data['subject']);
        self::assertArrayHasKey('OGRN', $data['subject']);
        self::assertArrayHasKey('INN', $data['subject']);
        self::assertArrayHasKey('surname', $data['subject']);
        self::assertArrayHasKey('name', $data['subject']);
        self::assertArrayHasKey('middleName', $data['subject']);
        self::assertArrayHasKey('SNILS', $data['subject']);

        // asserts issuer
        self::assertArrayHasKey('name', $data['issuer']);
        self::assertArrayHasKey('shortName', $data['issuer']);
        self::assertArrayHasKey('unitName', $data['issuer']);
        self::assertArrayHasKey('country', $data['issuer']);
        self::assertArrayHasKey('state', $data['issuer']);
        self::assertArrayHasKey('locality', $data['issuer']);
        self::assertArrayHasKey('address', $data['issuer']);
        self::assertArrayHasKey('email', $data['issuer']);
        self::assertArrayHasKey('OGRN', $data['issuer']);
        self::assertArrayHasKey('INN', $data['issuer']);
    }

    public function getCertificatePaths(): array
    {
        return [
            ['/../example/ivanov_crypto_2001_base64.cer'],
            ['/../example/ivanov_crypto_2001_der.cer'],
//            ['/../temp/official1.cer'],
//            ['/../temp/official2.cer'],
//            ['/../temp/person1.cer'],
//            ['/../temp/person2.cer'],
//            ['/../temp/company.cer'],
        ];
    }
}