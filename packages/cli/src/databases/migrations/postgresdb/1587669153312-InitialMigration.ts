import type { MigrationContext, ReversibleMigration } from '@db/types';

export class InitialMigration1587669153312 implements ReversibleMigration {
	async up({ schemaBuilder: { createTable, createIndex, column } }: MigrationContext) {
		await createTable('credentials_entity')
			.ifNotExists.withColumns(
				column('id').int.notNull.autoIncrement,
				column('name').varchar(128).notNull,
				column('data').text.notNull,
				column('type').varchar(32).notNull,
				column('nodesAccess').json.notNull,
				column('createdAt').datetime.notNull,
				column('updatedAt').datetime,
			)
			.withPrimaryKey('id');

		await createIndex('07fde106c0b471d8cc80a64fc8').ifNotExists.on('credentials_entity', ['type']);

		await createTable('execution_entity')
			.ifNotExists.withColumns(
				column('id').int.notNull.autoIncrement,
				column('data').text.notNull,
				column('finished').bool.notNull,
				column('mode').text.notNull,
				column('retryOf').text,
				column('retrySuccessId').text,
				column('startedAt').datetime.notNull,
				column('stoppedAt').datetime.notNull,
				column('workflowData').json.notNull,
				column('workflowId').text,
			)
			.withPrimaryKey('id');

		await createIndex('c4d999a5e90784e8caccf5589d').ifNotExists.on('execution_entity', [
			'workflowId',
		]);

		await createTable('workflow_entity')
			.ifNotExists.withColumns(
				column('id').int.notNull.autoIncrement,
				column('name').varchar(128).notNull,
				column('active').bool.notNull,
				column('nodes').json.notNull,
				column('connections').json.notNull,
				column('createdAt').datetime.notNull,
				column('updatedAt').datetime.notNull,
				column('settings').json,
				column('staticData').json,
			)
			.withPrimaryKey('id');
	}

	async down({ schemaBuilder: { dropIndex, dropTable } }: MigrationContext) {
		await dropTable('workflow_entity');
		await dropIndex('c4d999a5e90784e8caccf5589d');
		await dropTable('execution_entity');
		await dropIndex('07fde106c0b471d8cc80a64fc8');
		await dropTable('credentials_entity');
	}
}
