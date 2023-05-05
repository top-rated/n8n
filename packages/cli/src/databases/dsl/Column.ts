import type { Driver } from 'typeorm';

export class Column {
	private type: 'BOOLEAN' | 'INT' | 'VARCHAR' | 'TEXT' | 'JSON' | 'DATETIME';

	private length: number | 'auto';

	private additional: Set<'AUTO_INCREMENT' | 'NOT NULL'> = new Set();

	constructor(private name: string) {}

	get bool() {
		this.type = 'BOOLEAN';
		return this;
	}

	get int() {
		this.type = 'INT';
		return this;
	}

	varchar(length: number) {
		this.type = 'VARCHAR';
		this.length = length;
		return this;
	}

	get text() {
		this.type = 'TEXT';
		return this;
	}

	get json() {
		this.type = 'JSON';
		return this;
	}

	get datetime() {
		this.type = 'DATETIME';
		return this;
	}

	get autoIncrement() {
		this.additional.add('AUTO_INCREMENT');
		return this;
	}

	get notNull() {
		this.additional.add('NOT NULL');
		return this;
	}

	toSQL(driver: Driver) {
		const { name, type, length, additional } = this;
		const isPostgres = 'postgres' in driver;
		const isSqlite = 'sqlite' in driver;

		const sql = [driver.escape(name)];
		if (type === 'INT') {
			if (isPostgres && additional.has('AUTO_INCREMENT')) {
				sql.push('SERIAL');
				additional.delete('AUTO_INCREMENT');
			} else if (isSqlite) {
				sql.push('INTEGER');
			} else {
				sql.push(type);
			}
		} else if (type === 'VARCHAR') {
			sql.push(`VARCHAR(${length})`);
		} else if (type === 'DATETIME') {
			sql.push(isPostgres ? 'TIMESTAMP' : type);
		} else if (isSqlite && type === 'JSON') {
			sql.push('TEXT');
		} else {
			sql.push(type);
		}
		sql.push(...additional);
		return sql.join(' ');
	}
}
