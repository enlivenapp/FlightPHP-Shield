<?php

declare(strict_types=1);

namespace Enlivenapp\FlightShield\Tests\Unit;

use Enlivenapp\FlightShield\Result;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

#[CoversClass(Result::class)]
class ResultTest extends TestCase
{
    #[Test]
    public function defaultStateIsNotOk(): void
    {
        $result = new Result();

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function defaultReasonIsNull(): void
    {
        $result = new Result();

        $this->assertNull($result->reason());
    }

    #[Test]
    public function defaultExtraInfoIsNull(): void
    {
        $result = new Result();

        $this->assertNull($result->extraInfo());
    }

    #[Test]
    public function setSuccessTrueMakesIsOKReturnTrue(): void
    {
        $result = new Result();
        $result->setSuccess(true);

        $this->assertTrue($result->isOK());
    }

    #[Test]
    public function setSuccessFalseMakesIsOKReturnFalse(): void
    {
        $result = new Result();
        $result->setSuccess(true);
        $result->setSuccess(false);

        $this->assertFalse($result->isOK());
    }

    #[Test]
    public function setReasonStoresString(): void
    {
        $result = new Result();
        $result->setReason('Token expired');

        $this->assertSame('Token expired', $result->reason());
    }

    #[Test]
    public function setReasonAcceptsNull(): void
    {
        $result = new Result();
        $result->setReason('Something');
        $result->setReason(null);

        $this->assertNull($result->reason());
    }

    #[Test]
    public function setExtraInfoWithString(): void
    {
        $result = new Result();
        $result->setExtraInfo('extra data');

        $this->assertSame('extra data', $result->extraInfo());
    }

    #[Test]
    public function setExtraInfoWithArray(): void
    {
        $result = new Result();
        $result->setExtraInfo(['key' => 'value']);

        $this->assertSame(['key' => 'value'], $result->extraInfo());
    }

    #[Test]
    public function setExtraInfoWithObject(): void
    {
        $result = new Result();
        $obj    = new \stdClass();
        $result->setExtraInfo($obj);

        $this->assertSame($obj, $result->extraInfo());
    }

    #[Test]
    public function setExtraInfoWithInteger(): void
    {
        $result = new Result();
        $result->setExtraInfo(42);

        $this->assertSame(42, $result->extraInfo());
    }

    #[Test]
    public function setExtraInfoWithNull(): void
    {
        $result = new Result();
        $result->setExtraInfo('something');
        $result->setExtraInfo(null);

        $this->assertNull($result->extraInfo());
    }

    #[Test]
    public function setSuccessReturnsSameInstance(): void
    {
        $result   = new Result();
        $returned = $result->setSuccess(true);

        $this->assertSame($result, $returned);
    }

    #[Test]
    public function setReasonReturnsSameInstance(): void
    {
        $result   = new Result();
        $returned = $result->setReason('reason');

        $this->assertSame($result, $returned);
    }

    #[Test]
    public function setExtraInfoReturnsSameInstance(): void
    {
        $result   = new Result();
        $returned = $result->setExtraInfo('info');

        $this->assertSame($result, $returned);
    }

    #[Test]
    public function fluentChainingWorks(): void
    {
        $result = (new Result())
            ->setSuccess(true)
            ->setReason('all good')
            ->setExtraInfo(['code' => 200]);

        $this->assertTrue($result->isOK());
        $this->assertSame('all good', $result->reason());
        $this->assertSame(['code' => 200], $result->extraInfo());
    }
}
