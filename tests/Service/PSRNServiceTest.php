<?php

namespace AVKluchko\X509Bundle\Tests\Service;

use AVKluchko\X509Bundle\Service\PSRNService;
use PHPUnit\Framework\TestCase;

class PSRNServiceTest extends TestCase
{
    private $service;

    public function setUp(): void
    {
        $this->service = new PSRNService();
    }

    /**
     * @dataProvider provideValues
     */
    public function testIsPSRN(string $value, bool $expected)
    {
        $this->assertEquals($this->service->isPSRN($value), $expected);
    }

    public function provideValues(): array
    {
        return [
            ['', false],
            ['             ', false], // 13 whitespaces
            ['abcd123456789', false],
            ['1234567891577', false],
            ['1234567891579', true],
        ];
    }
}