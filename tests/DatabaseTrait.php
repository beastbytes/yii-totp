<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp\Tests;

use Yiisoft\Cache\ArrayCache;
use Yiisoft\Db\Cache\SchemaCache;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Sqlite\Connection;
use Yiisoft\Db\Sqlite\Driver;

trait DatabaseTrait
{
    protected function makeDatabase(): ConnectionInterface
    {
        $pdoDriver = new Driver(dsn: 'sqlite::memory:');
        $pdoDriver->charset('UTF8MB4');

        return new Connection($pdoDriver, new SchemaCache(new ArrayCache()));
    }
}