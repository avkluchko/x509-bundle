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
        date_default_timezone_set('Europe/Moscow');
        $this->parser = new Parser(new CertificateReader());
    }

    public function testPrivateKeyUsagePeriod(): void
    {
        self::assertNull($this->parser->parsePrivateKeyUsagePeriod([]));

        $result = $this->parser->parsePrivateKeyUsagePeriod([
            'privateKeyUsagePeriod' => 'Not Before: Jun 10 06:27:34 2019 GMT, Not After: Jun 10 06:05:54 2020 GMT'
        ]);

        self::assertEquals('2019-06-10 09:27:34', $result['from']->format('Y-m-d H:i:s'));
        self::assertEquals('2020-06-10 09:05:54', $result['to']->format('Y-m-d H:i:s'));

        $result = $this->parser->parsePrivateKeyUsagePeriod([
            'privateKeyUsagePeriod' => 'Not Before: May 28 09:25:22 2020 GMT, Not After: Aug 28 09:25:22 2021 GMT'
        ]);

        self::assertEquals('2020-05-28 12:25:22', $result['from']->format('Y-m-d H:i:s'));
        self::assertEquals('2021-08-28 12:25:22', $result['to']->format('Y-m-d H:i:s'));
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

    public function testParseExtendedKeyUsage(): void
    {
        self::assertNull($this->parser->parseExtendedKeyUsage([]));

        $result = $this->parser->parseExtendedKeyUsage([
            'extendedKeyUsage' => 'TLS Web Client Authentication, E-mail Protection, 1.2.643.2.1.6.8.5, 1.2.643.3.61.502710.1.6.3.2, 1.2.643.3.251.1.1, 1.2.643.3.251.3, 1.2.643.3.251.5.1, 1.2.643.3.251.6'
        ]);
        self::assertIsArray($result);
        self::assertEquals('TLS Web Client Authentication', $result[0]);
        self::assertEquals('1.2.643.3.251.6', $result[7]);
    }

    public function testParseEmail(): void
    {
        self::assertEquals('test@email.com', $this->parser->parseEmail('test@email.com'));
        self::assertEquals('new@email.com', $this->parser->parseEmail(['test@email.com', 'new@email.com']));
    }

    public function testParsePSNR(): void
    {
        self::assertEquals('1047797019830', $this->parser->parseOGRN(['OGRN' => '1047797019830']));

        self::assertEquals('1047797019830', $this->parser->parseOGRN([
            'undefined' => ['one value', '12345678983', '164400537302', '1047797019830', '1145678578']
        ]));

        self::assertNull($this->parser->parseOGRN([]));
        self::assertNull($this->parser->parseOGRN(['undefined' => ['one value', '1145678578', '12345678983']]));
    }

    public function testParseINN(): void
    {
        self::assertEquals('1145678578', $this->parser->parseINN(['INN' => '1145678578']));
        self::assertEquals('164400537302', $this->parser->parseINN(['INN' => '164400537302']));

        self::assertEquals('1145678578', $this->parser->parseINN([
            'undefined' => ['one value', '1047797019830', '1145678578']
        ]));

        self::assertEquals('164400537302', $this->parser->parseINN([
            'undefined' => ['one value', '12345678983', '164400537302', '1047797019830']
        ]));

        self::assertNull($this->parser->parseINN([]));
        self::assertNull($this->parser->parseINN(['undefined' => ['one value', '12345678983', '1047797019830']]));
    }

    public function testParseSNILS(): void
    {
        self::assertEquals('12345678964', $this->parser->parseSNILS(['SNILS' => '12345678964']));
        self::assertEquals('12345678964', $this->parser->parseSNILS(['SNILS' => '123-456-789 64']));

        self::assertEquals('12345678964', $this->parser->parseSNILS([
            'undefined' => ['one value', '1047797019830', '1145678578', '12345678964']
        ]));

        self::assertEquals('12345678964', $this->parser->parseSNILS([
            'undefined' => ['one value', '164400537302', '1047797019830', '123-456-789 64']
        ]));

        self::assertNull($this->parser->parseSNILS([]));
        self::assertNull($this->parser->parseSNILS(['undefined' => ['one value', '164400537302', '1047797019830']]));
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
        self::assertArrayHasKey('SNILS', $data['subject']);
        self::assertArrayHasKey('surname', $data['subject']);
        self::assertArrayHasKey('name', $data['subject']);
        self::assertArrayHasKey('middleName', $data['subject']);

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
//            ['/../example/ivanov_crypto_2001_base64.cer'],
//            ['/../example/ivanov_crypto_2001_der.cer'],
//            ['/../temp/official1.cer'],
//            ['/../temp/official2.cer'],
            ['/../temp/person1.cer'],
//            ['/../temp/person2.cer'],
//            ['/../temp/company.cer'],
        ];
    }
}