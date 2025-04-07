<?php

declare(strict_types=1);

namespace BeastBytes\Yii\Totp\Migration\int_pk;

use Yiisoft\Db\Exception\InvalidConfigException;
use Yiisoft\Db\Exception\NotSupportedException;
use Yiisoft\Db\Migration\MigrationBuilder;
use Yiisoft\Db\Migration\RevertibleMigrationInterface;
use Yiisoft\Db\Migration\TransactionalMigrationInterface;

final class M250404161325CreateTables implements RevertibleMigrationInterface, TransactionalMigrationInterface
{
    private const BACKUP_CODE_TABLENAME = 'otp_backup_code';
    private const TOTP_TABLENAME = 'totp';


    /**
     * @throws InvalidConfigException
     * @throws NotSupportedException
     */
    public function up(MigrationBuilder $b): void
    {
        $b->createTable(
            self::BACKUP_CODE_TABLENAME,
            [
                'id' => 'integer NOT NULL',
                'user_id' => 'integer NOT NULL',
                'code' => 'string(255) NOT NULL',
                'PRIMARY KEY ([[id]])',
            ],
        );
        $b->createIndex(self::BACKUP_CODE_TABLENAME, 'idx-otp_backup_codes-user_id', 'user_id');

        $b->createTable(
            self::TOTP_TABLENAME,
            [
                'user_id' => 'integer NOT NULL',
                'secret' => 'binary NOT NULL',
                'digest' => 'string(255) NOT NULL',
                'digits' => 'integer NOT NULL',
                'leeway' => 'integer NOT NULL',
                'period' => 'integer NOT NULL',
                'last_code' => 'string(6) NOT NULL',
                'PRIMARY KEY ([[user_id]])',
            ],
        );
    }

    /**
     * @throws InvalidConfigException
     * @throws NotSupportedException
     */
    public function down(MigrationBuilder $b): void
    {
        $b->dropTable(self::BACKUP_CODE_TABLENAME);
        $b->dropTable(self::TOTP_TABLENAME);
    }
}