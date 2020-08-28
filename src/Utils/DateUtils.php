<?php

namespace AVKluchko\X509Bundle\Utils;

class DateUtils
{
    public static function timeToDatetime(int $value): \DateTime
    {
        return new \DateTime(date('Y-m-d H:i:s', $value));
    }
}