import { mock } from 'jest-mock-extended';
import { DataSource } from 'typeorm';
import type { QueryRunner } from 'typeorm';
import { createSchemaBuilder } from '@/databases/dsl';
import type { DatabaseType } from '@/databases/types';
import { getConnectionOptions } from '@/Db';

describe('Migration DSL', () => {
	const tablePrefix = 'test_';

	beforeEach(() => {
		jest.restoreAllMocks();
	});

	const createQueryRunner = (dbType: DatabaseType) => {
		const connection = new DataSource(getConnectionOptions(dbType));
		const queryRunner = mock<QueryRunner>();
		Object.assign(queryRunner, { connection });
		jest.spyOn(connection.driver, 'createQueryRunner').mockReturnValue(queryRunner);
		queryRunner.query.mockResolvedValueOnce(undefined);
		return queryRunner;
	};

	describe('createTable', () => {
		const tests: Record<DatabaseType, string> = {
			mariadb:
				'CREATE TABLE IF NOT EXISTS `test_credentials_entity` (`id` INT NOT NULL AUTO_INCREMENT, `name` VARCHAR(128) NOT NULL, `data` TEXT NOT NULL, `type` VARCHAR(32) NOT NULL, `nodesAccess` JSON NOT NULL, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, INDEX `IDX_test_07fde106c0b471d8cc80a64fc8` (`type`), PRIMARY KEY (`id`)) ENGINE=InnoDB',
			mysqldb:
				'CREATE TABLE IF NOT EXISTS `test_credentials_entity` (`id` INT NOT NULL AUTO_INCREMENT, `name` VARCHAR(128) NOT NULL, `data` TEXT NOT NULL, `type` VARCHAR(32) NOT NULL, `nodesAccess` JSON NOT NULL, `createdAt` DATETIME NOT NULL, `updatedAt` DATETIME NOT NULL, INDEX `IDX_test_07fde106c0b471d8cc80a64fc8` (`type`), PRIMARY KEY (`id`)) ENGINE=InnoDB',
			postgresdb:
				'CREATE TABLE IF NOT EXISTS "test_credentials_entity" ("id" SERIAL NOT NULL, "name" VARCHAR(128) NOT NULL, "data" TEXT NOT NULL, "type" VARCHAR(32) NOT NULL, "nodesAccess" JSON NOT NULL, "createdAt" TIMESTAMP NOT NULL, "updatedAt" TIMESTAMP NOT NULL, CONSTRAINT PK_test_814c3d3c36e8a27fa8edb761b0e PRIMARY KEY ("id"))',
			sqlite:
				'CREATE TABLE IF NOT EXISTS "test_credentials_entity" ("id" INTEGER PRIMARY KEY NOT NULL AUTOINCREMENT, "name" VARCHAR(128) NOT NULL, "data" TEXT NOT NULL, "type" VARCHAR(32) NOT NULL, "nodesAccess" TEXT NOT NULL, "createdAt" DATETIME NOT NULL, "updatedAt" DATETIME NOT NULL)`',
		} as const;

		Object.keys(tests).forEach((dbType: DatabaseType) =>
			test(dbType, async () => {
				const queryRunner = createQueryRunner(dbType);
				const { createTable, column } = createSchemaBuilder(tablePrefix, queryRunner);

				await createTable('credentials_entity')
					.ifNotExists.withColumns(
						column('id').int.notNull.autoIncrement,
						column('name').varchar(128).notNull,
						column('data').text.notNull,
						column('type').varchar(32).notNull,
						column('nodesAccess').json.notNull,
						column('createdAt').datetime.notNull,
						column('updatedAt').datetime.notNull,
					)
					.withPrimaryKey('id');

				expect(queryRunner.query.mock.calls[0][0]).toEqual(tests[dbType]);
			}),
		);
	});

	describe('createIndex', () => {
		const tests: Record<DatabaseType, string> = {
			mariadb:
				'CREATE INDEX IF NOT EXISTS `IDX_test_07fde106c0b471d8cc80a64fc8` ON `test_credentials_entity` (`type`)',
			mysqldb:
				'CREATE INDEX IF NOT EXISTS `IDX_test_07fde106c0b471d8cc80a64fc8` ON `test_credentials_entity` (`type`)',
			postgresdb:
				'CREATE INDEX IF NOT EXISTS "IDX_test_07fde106c0b471d8cc80a64fc8" ON "test_credentials_entity" ("type")',
			sqlite:
				'CREATE INDEX IF NOT EXISTS "IDX_test_07fde106c0b471d8cc80a64fc8" ON "test_credentials_entity" ("type")',
		} as const;

		Object.keys(tests).forEach((dbType: DatabaseType) =>
			test(dbType, async () => {
				const queryRunner = createQueryRunner(dbType);
				const { createIndex } = createSchemaBuilder(tablePrefix, queryRunner);

				await createIndex('07fde106c0b471d8cc80a64fc8').ifNotExists.on('credentials_entity', [
					'type',
				]);

				expect(queryRunner.query.mock.calls[0][0]).toEqual(tests[dbType]);
			}),
		);
	});

	describe('dropIndex', () => {
		const tests: Record<DatabaseType, string> = {
			mariadb: 'DROP INDEX IF EXISTS `IDX_test_07fde106c0b471d8cc80a64fc8`',
			mysqldb: 'DROP INDEX IF EXISTS `IDX_test_07fde106c0b471d8cc80a64fc8`',
			postgresdb: 'DROP INDEX IF EXISTS "IDX_test_07fde106c0b471d8cc80a64fc8"',
			sqlite: 'DROP INDEX IF EXISTS "IDX_test_07fde106c0b471d8cc80a64fc8"',
		} as const;

		Object.keys(tests).forEach((dbType: DatabaseType) =>
			test(dbType, async () => {
				const queryRunner = createQueryRunner(dbType);
				const { dropIndex } = createSchemaBuilder(tablePrefix, queryRunner);
				await dropIndex('07fde106c0b471d8cc80a64fc8').ifExists;

				expect(queryRunner.query.mock.calls[0][0]).toEqual(tests[dbType]);
			}),
		);
	});

	describe('dropTable', () => {
		const tests: Record<DatabaseType, string> = {
			mariadb: 'DROP TABLE IF EXISTS `test_credentials_entity`',
			mysqldb: 'DROP TABLE IF EXISTS `test_credentials_entity`',
			postgresdb: 'DROP TABLE IF EXISTS "test_credentials_entity"',
			sqlite: 'DROP TABLE IF EXISTS "test_credentials_entity"',
		} as const;

		Object.keys(tests).forEach((dbType: DatabaseType) =>
			test(dbType, async () => {
				const queryRunner = createQueryRunner(dbType);
				const { dropTable } = createSchemaBuilder(tablePrefix, queryRunner);
				await dropTable('credentials_entity').ifExists;

				expect(queryRunner.query.mock.calls[0][0]).toEqual(tests[dbType]);
			}),
		);
	});
});
