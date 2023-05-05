import type { Driver, QueryRunner } from 'typeorm';
import type { Column } from './Column';
import { LazyPromise } from 'n8n-workflow';

abstract class TableOperation extends LazyPromise<void> {
	abstract toSQL(driver: Driver): string;

	constructor(protected name: string, protected prefix: string, queryRunner: QueryRunner) {
		super((resolve) => {
			const sql = this.toSQL(queryRunner.connection.driver);
			void queryRunner.query(sql).then(resolve);
		});
	}
}

abstract class CreateOperation extends TableOperation {
	protected onlyIfNotExists: boolean;

	get ifNotExists() {
		this.onlyIfNotExists = true;
		return this;
	}
}

export class CreateTable extends CreateOperation {
	private columns: Column[];

	private primaryKey: string[] = [];

	withColumns(...columns: Column[]) {
		this.columns = columns;
		return this;
	}

	withPrimaryKey(...primaryKey: string[]) {
		this.primaryKey = primaryKey;
		return this;
	}

	toSQL(driver: Driver) {
		const { columns, primaryKey, name, prefix, onlyIfNotExists } = this;
		const isMysql = 'mysql' in driver;
		const isSqlite = 'sqlite' in driver;

		const sql = ['CREATE TABLE'];
		if (onlyIfNotExists) sql.push('IF NOT EXISTS');
		sql.push(driver.escape(`${prefix}${name}`));
		const columnsSql = columns.map((c) => c.toSQL(driver));
		if (primaryKey.length) {
			if (isSqlite) {
				// TODO: add primary key for sqlite
			} else {
				columnsSql.push(`PRIMARY KEY (${primaryKey.map((p) => driver.escape(p)).join(', ')})`);
			}
		}
		sql.push(`(${columnsSql.join(', ')})`);
		if (isMysql) {
			sql.push('ENGINE=InnoDB');
		}
		return sql.join(' ');
	}
}

export class CreateIndex extends CreateOperation {
	private tableName: string;

	private columns: string[];

	on(tableName: string, columns: string[]) {
		this.tableName = tableName;
		this.columns = columns;
		return this;
	}

	toSQL(driver: Driver) {
		const { name, tableName, columns, prefix, onlyIfNotExists } = this;
		const sql = ['CREATE INDEX'];
		if (onlyIfNotExists) sql.push('IF NOT EXISTS');
		sql.push(driver.escape(`IDX_${prefix}${name}`), 'ON', driver.escape(`${prefix}${tableName}`));
		sql.push(`(${columns.map((c) => driver.escape(c)).join(', ')})`);
		return sql.join(' ');
	}
}

abstract class DropOperation extends TableOperation {
	protected onlyIfExists: boolean;

	get ifExists() {
		this.onlyIfExists = true;
		return this;
	}
}

export class DropIndex extends DropOperation {
	toSQL(driver: Driver) {
		const { name, prefix, onlyIfExists } = this;
		const sql = ['DROP INDEX'];
		if (onlyIfExists) sql.push('IF EXISTS');
		sql.push(driver.escape(`IDX_${prefix}${name}`));
		return sql.join(' ');
	}
}

export class DropTable extends DropOperation {
	toSQL(driver: Driver) {
		const { name, prefix, onlyIfExists } = this;
		const sql = ['DROP TABLE'];
		if (onlyIfExists) sql.push('IF EXISTS');
		sql.push(driver.escape(`${prefix}${name}`));
		return sql.join(' ');
	}
}
