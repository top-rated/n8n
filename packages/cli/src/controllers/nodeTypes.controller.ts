import { readFile } from 'fs/promises';
import get from 'lodash.get';
import { Request } from 'express';
import { LoadMappingOptions, LoadNodeListSearch, LoadNodeParameterOptions } from 'n8n-core';
import type {
	INodeCredentials,
	INodeListSearchResult,
	INodeParameters,
	INodePropertyOptions,
	INodeTypeDescription,
	INodeTypeNameVersion,
	ResourceMapperFields,
} from 'n8n-workflow';
import { jsonParse } from 'n8n-workflow';
import { Authorized, Get, Post, RestController } from '@/decorators';
import { getNodeTranslationPath } from '@/TranslationHelpers';
import { Config } from '@/config';
import { NodeTypes } from '@/NodeTypes';
import { NodeTypesRequest } from '@/requests';
import { BadRequestError } from '@/ResponseHelper';
import * as WorkflowExecuteAdditionalData from '@/WorkflowExecuteAdditionalData';

@Authorized()
@RestController('/node-types')
export class NodeTypesController {
	constructor(private readonly config: Config, private readonly nodeTypes: NodeTypes) {}

	@Post('/')
	async getNodeInfo(req: Request) {
		const nodeInfos = get(req, 'body.nodeInfos', []) as INodeTypeNameVersion[];

		const defaultLocale = this.config.getEnv('defaultLocale');

		if (defaultLocale === 'en') {
			return nodeInfos.reduce<INodeTypeDescription[]>((acc, { name, version }) => {
				const { description } = this.nodeTypes.getByNameAndVersion(name, version);
				acc.push(description);
				return acc;
			}, []);
		}

		const populateTranslation = async (
			name: string,
			version: number,
			nodeTypes: INodeTypeDescription[],
		) => {
			const { description, sourcePath } = this.nodeTypes.getWithSourcePath(name, version);
			const translationPath = await getNodeTranslationPath({
				nodeSourcePath: sourcePath,
				longNodeType: description.name,
				locale: defaultLocale,
			});

			try {
				const translation = await readFile(translationPath, 'utf8');
				// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
				description.translation = JSON.parse(translation);
			} catch {
				// ignore - no translation exists at path
			}

			nodeTypes.push(description);
		};

		const nodeTypes: INodeTypeDescription[] = [];

		const promises = nodeInfos.map(async ({ name, version }) =>
			populateTranslation(name, version, nodeTypes),
		);

		await Promise.all(promises);

		return nodeTypes;
	}

	@Get('/mapping-fields')
	async getMappingFields(
		req: NodeTypesRequest.GetMappingFields,
	): Promise<ResourceMapperFields | undefined> {
		const { path, methodName } = req.query;
		const { nodeTypeAndVersion, currentNodeParameters, credentials, additionalData } =
			await this.validateRequest(req);

		const loadMappingOptionsInstance = new LoadMappingOptions(
			nodeTypeAndVersion,
			this.nodeTypes,
			path,
			currentNodeParameters,
			credentials,
		);

		return loadMappingOptionsInstance.getOptionsViaMethodName(methodName, additionalData);
	}

	// Returns parameter values which normally get loaded from an external API or get generated dynamically
	@Get('/parameter-options')
	async getParameterOptions(
		req: NodeTypesRequest.GetParameterOptions,
	): Promise<INodePropertyOptions[]> {
		const { path, methodName } = req.query;
		const { nodeTypeAndVersion, currentNodeParameters, credentials, additionalData } =
			await this.validateRequest(req);

		const loadDataInstance = new LoadNodeParameterOptions(
			nodeTypeAndVersion,
			this.nodeTypes,
			path,
			currentNodeParameters,
			credentials,
		);

		if (methodName) {
			return loadDataInstance.getOptionsViaMethodName(methodName, additionalData);
		}
		// @ts-ignore
		if (req.query.loadOptions) {
			return loadDataInstance.getOptionsViaRequestProperty(
				// @ts-ignore
				jsonParse(req.query.loadOptions as string),
				additionalData,
			);
		}

		return [];
	}

	@Get('/list-search')
	async listSearch(req: NodeTypesRequest.ListSearch): Promise<INodeListSearchResult | undefined> {
		const { path, methodName } = req.query;
		if (!methodName) throw new BadRequestError('Parameter methodName is required.');

		const { nodeTypeAndVersion, currentNodeParameters, credentials, additionalData } =
			await this.validateRequest(req);

		const listSearchInstance = new LoadNodeListSearch(
			nodeTypeAndVersion,
			this.nodeTypes,
			path,
			currentNodeParameters,
			credentials,
		);

		return listSearchInstance.getOptionsViaMethodName(
			methodName,
			additionalData,
			req.query.filter,
			req.query.paginationToken,
		);
	}

	private async validateRequest(req: NodeTypesRequest.BaseRequest) {
		const nodeTypeAndVersion = this.parseQueryParam<INodeTypeNameVersion>(
			req,
			'nodeTypeAndVersion',
		);
		const currentNodeParameters = this.parseQueryParam<INodeParameters>(
			req,
			'currentNodeParameters',
		);

		let credentials: INodeCredentials | undefined;
		if (req.query.credentials) {
			credentials = jsonParse(req.query.credentials);
		}

		const additionalData = await WorkflowExecuteAdditionalData.getBase(
			req.user.id,
			currentNodeParameters,
		);

		return { nodeTypeAndVersion, currentNodeParameters, credentials, additionalData };
	}

	private parseQueryParam<T>(
		req: NodeTypesRequest.BaseRequest,
		paramName: keyof NodeTypesRequest.BaseRequest['query'],
	) {
		if (!req.query[paramName]) {
			throw new BadRequestError(`Parameter ${paramName} is required.`);
		}
		return jsonParse<T>(req.query[paramName]);
	}
}
