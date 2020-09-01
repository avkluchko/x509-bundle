<?php

namespace AVKluchko\X509Bundle\Tests\Utils;

use AVKluchko\X509Bundle\Utils\DateUtils;
use PHPUnit\Framework\TestCase;

class DateUtilsTest extends TestCase
{
    protected function setUp(): void
    {
        date_default_timezone_set('Europe/Moscow');
    }

    public function testTimeToDatetime_MustReturnDatetime():void
    {
        $date = DateUtils::timeToDatetime(1571133507);
        self::assertEquals('2019-10-15 12:58:27', $date->format('Y-m-d H:i:s'));

        $date = DateUtils::timeToDatetime(1890902733);
        self::assertEquals('2029-12-02 13:45:33', $date->format('Y-m-d H:i:s'));
    }
}