/* eslint-disable @typescript-eslint/promise-function-async */
import type { QueryRunner } from 'typeorm';
import { Column } from './Column';
import { CreateTable, CreateIndex, DropTable, DropIndex } from './Table';

export const createSchemaBuilder = (tablePrefix: string, queryRunner: QueryRunner) => ({
	column: (name: string) => new Column(name),
	createTable: (name: string) => new CreateTable(name, tablePrefix, queryRunner),
	createIndex: (name: string) => new CreateIndex(name, tablePrefix, queryRunner),
	dropIndex: (name: string) => new DropIndex(name, tablePrefix, queryRunner),
	dropTable: (name: string) => new DropTable(name, tablePrefix, queryRunner),
});
