import type { IRestApiContext, ExternalSecretsProvider } from '@/Interface';

const infisical: ExternalSecretsProvider = {
	id: 'infisical',
	name: 'Infisical',
	connectable: true,
	connected: true,
	connectedAt: '2021-09-01T00:00:00.000Z',
	properties: [
		{
			displayName: 'Need help filling out these fields? <a href="https://n8n.io">Open docs</a>',
			name: 'notice',
			type: 'notice',
			default: '',
		},
		{
			displayName: 'Token',
			name: 'token',
			type: 'string',
			default: '',
			placeholder: 'e.g. fe333bd8-37f9-40aa-a9f8-d54dce389f17',
			required: true,
			noDataExpression: true,
		},
		{
			displayName: 'Site URL',
			name: 'siteUrl',
			type: 'string',
			default: '',
			placeholder: 'e.g. https://app.infisical.com',
			noDataExpression: true,
		},
		{
			displayName: 'Cache TTL',
			name: 'cacheTTL',
			type: 'number',
			default: '',
			placeholder: 'e.g. 500',
			noDataExpression: true,
		},
		{
			displayName: 'Debug',
			name: 'debug',
			type: 'boolean',
			default: '',
			noDataExpression: true,
		},
	],
	data: {
		token: 'fe333bd8-37f9-40aa-a9f8-d54dce389f17',
		siteUrl: '',
		cacheTTL: 500,
		debug: false,
	},
};

const doppler: ExternalSecretsProvider = {
	id: 'doppler',
	name: 'Doppler',
	connected: false,
	connectedAt: '',
	properties: [
		{
			displayName: 'Need help filling out these fields? <a href="https://n8n.io">Open docs</a>',
			name: 'notice',
			type: 'notice',
			default: '',
		},
		{
			displayName: 'Token',
			name: 'token',
			type: 'string',
			default: '',
			placeholder: 'e.g. fe333bd8-37f9-40aa-a9f8-d54dce389f17',
			required: true,
			noDataExpression: true,
		},
		{
			displayName: 'Site URL',
			name: 'siteUrl',
			type: 'string',
			default: '',
			placeholder: 'e.g. https://app.infisical.com',
			noDataExpression: true,
		},
		{
			displayName: 'Cache TTL',
			name: 'cacheTTL',
			type: 'number',
			default: '',
			placeholder: 'e.g. 500',
			noDataExpression: true,
		},
		{
			displayName: 'Debug',
			name: 'debug',
			type: 'boolean',
			default: '',
			noDataExpression: true,
		},
	],
	data: {},
};

export const getExternalSecrets = async (
	context: IRestApiContext,
): Promise<Record<string, string[]>> => {
	return {
		infisical: ['EXAMPLE'],
	};
	// return makeRestApiRequest(context, 'GET', '/external-secrets');
};

export const getExternalSecretsProviders = async (
	context: IRestApiContext,
): Promise<ExternalSecretsProvider[]> => {
	return [infisical, doppler];
	// return makeRestApiRequest(context, 'GET', '/external-secrets/providers');
};

export const getExternalSecretsProvider = async (
	context: IRestApiContext,
	id: string,
): Promise<ExternalSecretsProvider> => {
	return {
		infisical,
		doppler,
	}[id]!;
	// return makeRestApiRequest(context, 'GET', '/external-secrets/provider/infisical');
};

export const updateProvider = async (
	context: IRestApiContext,
	id: string,
	data: Partial<ExternalSecretsProvider>,
): Promise<boolean> => {
	return true;
	// return makeRestApiRequest(context, 'GET', '/external-secrets/provider/infisical');
};
