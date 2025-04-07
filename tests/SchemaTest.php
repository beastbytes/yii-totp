<?php

namespace BeastBytes\Yii\Totp\Tests;

use PHPUnit\Framework\Attributes\BeforeClass;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\ExpectationFailedException;
use RuntimeException;
use Yiisoft\Db\Constraint\Constraint;

class SchemaTest extends TestCase
{
    use DatabaseTrait;

    private static array $tableSchemas = [
        'otp_backup_code' => [
            'id' => [
                'index' => [
                    'type' => 'primary',
                ],
                'type' => 'integer',
                'size' => null,
                'null' => false,
            ],
            'user_id' => [
                'index' => [
                    'type' => 'index',
                    'name' => 'idx-otp_backup_codes-user_id',
                    'isUnique' => false,
                ],
                'type' => 'integer',
                'size' => null,
                'null' => false,
            ],
            'code' => [
                'type' => 'string',
                'size' => 255,
                'null' => false,
            ],
        ],
        'totp' => [
            'user_id' => [
                'index' => [
                    'type' => 'primary',
                ],
                'type' => 'integer',
                'size' => null,
                'null' => false,
            ],
            'secret' => [
                'type' => 'binary',
                'null' => false,
            ],
            'digest' => [
                'type' => 'string',
                'size' => 255,
                'null' => false,
            ],
            'digits' => [
                'type' => 'integer',
                'size' => null,
                'null' => false,
            ],
            'leeway' => [
                'type' => 'integer',
                'size' => null,
                'null' => false,
            ],
            'period' => [
                'type' => 'integer',
                'size' => null,
                'null' => false,
            ],
            'last_code' => [
                'type' => 'string',
                'size' => 6,
                'null' => false,
            ],
        ],
    ];

    #[BeforeClass]
    public static function init(): void
    {
        $params = require dirname(__DIR__) . '/config/params.php';

        foreach ($params['beastbytes/yii-totp']['database'] as $tableName) {
            if (!array_key_exists($tableName, self::$tableSchemas)) {
                throw new RuntimeException(sprintf('%s not defined in self::$tableSchemas', $tableName));
            }
        }
    }

    #[Test]
    public function schema(): void
    {
        $this->checkNoTables();

        $this->runMigrations();
        $this->checkTables();

        $this->rollbackMigrations();
        $this->checkNoTables();
    }

    private function checkNoTables(): void
    {
        foreach (array_keys(self::$tableSchemas) as $tableName) {
            $this->assertNull(
                $this
                    ->getDatabase()
                    ->getSchema()
                    ->getTableSchema($tableName)
            );
        }
    }

    private function checkTables(): void
    {
        $database = $this->getDatabase();
        $databaseSchema = $database->getSchema();

        foreach (self::$tableSchemas as $tableName => $columnSchemas) {
            $foreignKeys = $indexes = 0;
            $table = $databaseSchema->getTableSchema($tableName);

            $this->assertNotNull($table);

            $columns = $table->getColumns();

            foreach ($columnSchemas as $name => $columnSchema) {
                $this->assertArrayHasKey($name, $columns);
                $column = $columns[$name];
                $this->assertSame($columnSchema['type'], $column->getType());
                if (array_key_exists('size', $columnSchema)) {
                    $this->assertSame($columnSchema['size'], $column->getSize());
                }
                $columnSchema['null']
                    ? $this->assertTrue($column->isAllowNull())
                    : $this->assertFalse($column->isAllowNull())
                ;

                if (array_key_exists('foreignKeys', $columnSchema) && $columnSchema['foreignKeys'] === true) {
                    $foreignKeys++;
                }

                if (array_key_exists('index', $columnSchema)) {
                    if (($columnSchema['index']['type']) === 'primary') {
                        $primaryKey = $databaseSchema->getTablePrimaryKey($tableName);
                        $this->assertInstanceOf(Constraint::class, $primaryKey);
                        $this->assertSame([$name], $primaryKey->getColumnNames());
                    } else {
                        $indexes++;
                        $this->assertIndex(
                            table: $tableName,
                            expectedColumnNames: [$name],
                            expectedName: $columnSchema['index']['name'],
                            expectedIsUnique: $columnSchema['index']['isUnique']
                        );
                    }
                }
            }

            $this->assertCount($foreignKeys, $databaseSchema->getTableForeignKeys($tableName));
            $this->assertCount($indexes, $databaseSchema->getTableIndexes($tableName));
        }
    }

    protected function assertIndex(
        string $table,
        array $expectedColumnNames,
        ?string $expectedName = null,
        bool $expectedIsUnique = false,
        bool $expectedIsPrimary = false,
    ): void
    {
        $indexes = $this
            ->getDatabase()
            ->getSchema()
            ->getTableIndexes($table)
        ;
        $found = false;
        foreach ($indexes as $index) {
            try {
                $this->assertEqualsCanonicalizing($expectedColumnNames, $index->getColumnNames());
            } catch (ExpectationFailedException) {
                continue;
            }

            $found = true;

            $this->assertSame($expectedIsUnique, $index->isUnique());
            $this->assertSame($expectedIsPrimary, $index->isPrimary());

            if ($expectedName !== null) {
                $this->assertSame($expectedName, $index->getName());
            }
        }

        if (!$found) {
            self::fail('Index not found.');
        }
    }
}