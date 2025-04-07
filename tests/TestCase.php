<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp\Tests;

use PHPUnit\Framework\Attributes\BeforeClass;
use Symfony\Component\Console\Helper\HelperSet;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\ArrayInput;
use Symfony\Component\Console\Output\NullOutput;
use Yiisoft\Db\Connection\ConnectionInterface;
use Yiisoft\Db\Migration\Command\DownCommand;
use Yiisoft\Db\Migration\Command\UpdateCommand;
use Yiisoft\Db\Migration\Informer\NullMigrationInformer;
use Yiisoft\Db\Migration\Migrator;
use Yiisoft\Db\Migration\Runner\DownRunner;
use Yiisoft\Db\Migration\Runner\UpdateRunner;
use Yiisoft\Db\Migration\Service\MigrationService;
use Yiisoft\Injector\Injector;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    protected static ?ConnectionInterface $database = null;
    private ?DownCommand $migrateDownCommand = null;
    private ?UpdateCommand $migrateUpdateCommand = null;

    protected static array $params;

    #[BeforeClass]
    public static function init(): void
    {
        self::$params = require dirname(__DIR__) . '/config/params.php';
    }

    protected function getDatabase(): ConnectionInterface
    {
        if (self::$database === null) {
            self::$database = $this->makeDatabase();
        }

        return self::$database;
    }

    protected function getMigrateUpdateCommand(): UpdateCommand
    {
        if ($this->migrateUpdateCommand !== null) {
            return $this->migrateUpdateCommand;
        }

        $migrator = new Migrator($this->getDatabase(), new NullMigrationInformer());
        $this->migrateUpdateCommand = new UpdateCommand(
            new UpdateRunner($migrator),
            $this->getMigrationService($migrator),
            $migrator
        );
        $this->migrateUpdateCommand->setHelperSet(new HelperSet([
            'question' => new QuestionHelper(),
        ]));

        return $this->migrateUpdateCommand;
    }

    protected function getMigrateDownCommand(): DownCommand
    {
        if ($this->migrateDownCommand !== null) {
            return $this->migrateDownCommand;
        }

        $migrator = new Migrator($this->getDatabase(), new NullMigrationInformer());
        $this->migrateDownCommand = new DownCommand(
            new DownRunner($migrator),
            $this->getMigrationService($migrator),
            $migrator
        );
        $this->migrateDownCommand->setHelperSet(new HelperSet([
            'question' => new QuestionHelper(),
        ]));

        return $this->migrateDownCommand;
    }

    public static function tearDownAfterClass(): void
    {
        (new static(static::class))->rollbackMigrations();
    }

    protected function runMigrations(): void
    {
        $input = new ArrayInput([]);
        $input->setInteractive(false);

        $this->getMigrateUpdateCommand()->run($input, new NullOutput());
    }

    protected function rollbackMigrations(): void
    {
        $input = new ArrayInput(['--all' => true]);
        $input->setInteractive(false);

        $this->getMigrateDownCommand()->run($input, new NullOutput());
    }

    private function getMigrationService(Migrator $migrator): MigrationService
    {
        $migrationService = new MigrationService($this->getDatabase(), new Injector(), $migrator);
        $migrationService->setSourceNamespaces(['BeastBytes\\Yii\\Totp\\Migration\\int_pk']);

        return $migrationService;
    }

    abstract protected function makeDatabase(): ConnectionInterface;
}