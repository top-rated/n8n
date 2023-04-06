import type { ClientOAuth2Options } from '@n8n/client-oauth2';
import { ClientOAuth2 } from '@n8n/client-oauth2';
import Csrf from 'csrf';
import { Response } from 'express';
import { Repository } from 'typeorm';
import get from 'lodash.get';
import omit from 'lodash.omit';
import set from 'lodash.set';
import split from 'lodash.split';
import unset from 'lodash.unset';
import { resolve } from 'path';
import { jsonStringify, ILogger } from 'n8n-workflow';
import { TEMPLATES_DIR } from '@/constants';
import { Config } from '@/config';
import { Get, RestController } from '@/decorators';
import type { SharedCredentials } from '@db/entities/SharedCredentials';
import { CredentialsHelper } from '@/CredentialsHelper';
import { OAuthRequest } from '@/requests';
import { IExternalHooksClass } from '@/Interfaces';
import type { ICredentialsDb } from '@/Interfaces';
import { AbstractOAuthController } from './abstractOAuth.controller';

@RestController('/oauth2-credential')
export class OAuth2CredentialController extends AbstractOAuthController {
	constructor(
		config: Config,
		logger: ILogger,
		credentialsHelper: CredentialsHelper,
		private externalHooks: IExternalHooksClass,
		credentialsRepository: Repository<ICredentialsDb>,
		sharedCredentialsRepository: Repository<SharedCredentials>,
	) {
		super(2, config, logger, credentialsHelper, credentialsRepository, sharedCredentialsRepository);
	}

	/**
	 * Get Authorization url
	 */
	@Get('/auth')
	async getAuthUri(req: OAuthRequest.OAuth2Credential.Auth): Promise<string> {
		const credential = await this.getCredential(req);
		const decryptedDataOriginal = await this.getDecryptedData(credential);

		// At some point in the past we saved hidden scopes to credentials (but shouldn't)
		// Delete scope before applying defaults to make sure new scopes are present on reconnect
		// Generic Oauth2 API is an exception because it needs to save the scope
		const genericOAuth2 = ['oAuth2Api', 'googleOAuth2Api', 'microsoftOAuth2Api'];
		if (
			decryptedDataOriginal?.scope &&
			credential.type.includes('OAuth2') &&
			!genericOAuth2.includes(credential.type)
		) {
			delete decryptedDataOriginal.scope;
		}

		const oauthCredentials = this.applyDefaultsAndOverwrites(credential, decryptedDataOriginal);

		const token = new Csrf();
		// Generate a CSRF prevention token and send it as an OAuth2 state string
		const csrfSecret = token.secretSync();
		const state = {
			token: token.create(csrfSecret),
			cid: credential.id,
		};
		const stateEncodedStr = Buffer.from(JSON.stringify(state)).toString('base64');

		const oAuthOptions: ClientOAuth2Options = {
			clientId: get(oauthCredentials, 'clientId') as string,
			clientSecret: get(oauthCredentials, 'clientSecret', '') as string,
			accessTokenUri: get(oauthCredentials, 'accessTokenUrl', '') as string,
			authorizationUri: get(oauthCredentials, 'authUrl', '') as string,
			redirectUri: `${this.baseUrl}/callback`,
			scopes: split(get(oauthCredentials, 'scope', 'openid,') as string, ','),
			state: stateEncodedStr,
		};

		await this.externalHooks.run('oauth2.authenticate', [oAuthOptions]);

		const oAuthObj = new ClientOAuth2(oAuthOptions);
		const authQueryParameters = get(oauthCredentials, 'authQueryParameters', '') as string;
		let returnUri = oAuthObj.code.getUri();

		// if scope uses comma, change it as the library always return then with spaces
		const scope = get(oauthCredentials, 'scope') as string;
		if (scope?.includes(',')) {
			const data = returnUri.split('?')[1];
			const percentEncoded = [data, `scope=${encodeURIComponent(scope)}`].join('&');
			returnUri = `${get(oauthCredentials, 'authUrl', '') as string}?${percentEncoded}`;
		}

		if (authQueryParameters) {
			returnUri += `&${authQueryParameters}`;
		}

		await this.encryptAndSaveData(credential, decryptedDataOriginal);

		this.logger.verbose('OAuth2 authentication successful for new credential', {
			userId: req.user.id,
			credentialId: credential.id,
		});

		return returnUri;
	}

	/**
	 * Verify and store app code. Generate access tokens and store for respective credential.
	 */
	@Get('/callback')
	async handleCallback(req: OAuthRequest.OAuth2Credential.Callback, res: Response) {
		try {
			// realmId it's currently just use for the quickbook OAuth2 flow
			const { code, state: stateEncoded } = req.query;

			if (!code || !stateEncoded) {
				return this.renderCallbackError(
					res,
					'Insufficient parameters for OAuth2 callback.',
					`Received following query parameters: ${JSON.stringify(req.query)}`,
				);
			}

			let state;
			try {
				state = JSON.parse(Buffer.from(stateEncoded, 'base64').toString()) as {
					cid: string;
					token: string;
				};
			} catch (error) {
				return this.renderCallbackError(res, 'Invalid state format returned');
			}

			const credential = await this.getCredentialWithoutUser(state.cid);

			if (!credential) {
				const errorMessage = 'OAuth2 callback failed because of insufficient permissions';
				this.logger.error(errorMessage, {
					userId: req.user?.id,
					credentialId: state.cid,
				});
				return this.renderCallbackError(res, errorMessage);
			}

			const decryptedDataOriginal = await this.getDecryptedData(credential);
			const oauthCredentials = this.applyDefaultsAndOverwrites(credential, decryptedDataOriginal);

			const token = new Csrf();
			if (
				decryptedDataOriginal.csrfSecret === undefined ||
				!token.verify(decryptedDataOriginal.csrfSecret as string, state.token)
			) {
				const errorMessage = 'The OAuth2 callback state is invalid!';
				this.logger.debug(errorMessage, {
					userId: req.user?.id,
					credentialId: credential.id,
				});
				return this.renderCallbackError(res, errorMessage);
			}

			let options: Partial<ClientOAuth2Options> = {};

			const oAuth2Parameters: ClientOAuth2Options = {
				clientId: get(oauthCredentials, 'clientId') as string,
				clientSecret: get(oauthCredentials, 'clientSecret', '') as string,
				accessTokenUri: get(oauthCredentials, 'accessTokenUrl', '') as string,
				authorizationUri: get(oauthCredentials, 'authUrl', '') as string,
				redirectUri: `${this.baseUrl}/callback`,
				scopes: split(get(oauthCredentials, 'scope', 'openid,') as string, ','),
			};

			if ((get(oauthCredentials, 'authentication', 'header') as string) === 'body') {
				options = {
					body: {
						client_id: get(oauthCredentials, 'clientId') as string,
						client_secret: get(oauthCredentials, 'clientSecret', '') as string,
					},
				};
				// @ts-ignore
				delete oAuth2Parameters.clientSecret;
			}

			await this.externalHooks.run('oauth2.callback', [oAuth2Parameters]);

			const oAuthObj = new ClientOAuth2(oAuth2Parameters);

			const queryParameters = req.originalUrl.split('?').splice(1, 1).join('');

			const oauthToken = await oAuthObj.code.getToken(
				`${oAuth2Parameters.redirectUri as string}?${queryParameters}`,
				// @ts-ignore
				options,
			);

			if (Object.keys(req.query).length > 2) {
				set(oauthToken.data, 'callbackQueryString', omit(req.query, 'state', 'code'));
			}

			if (oauthToken === undefined) {
				const errorMessage = 'Unable to get OAuth2 access tokens!';
				this.logger.error(errorMessage, {
					userId: req.user?.id,
					credentialId: credential.id,
				});
				return this.renderCallbackError(res, errorMessage);
			}

			if (decryptedDataOriginal.oauthTokenData) {
				// Only overwrite supplied data as some providers do for example just return the
				// refresh_token on the very first request and not on subsequent ones.
				Object.assign(decryptedDataOriginal.oauthTokenData, oauthToken.data);
			} else {
				// No data exists so simply set
				decryptedDataOriginal.oauthTokenData = oauthToken.data;
			}

			// eslint-disable-next-line @typescript-eslint/no-unsafe-call
			unset(decryptedDataOriginal, 'csrfSecret');

			await this.encryptAndSaveData(credential, decryptedDataOriginal);

			this.logger.verbose('OAuth2 callback successful for new credential', {
				userId: req.user?.id,
				credentialId: credential.id,
			});

			return res.sendFile(resolve(TEMPLATES_DIR, 'oauth-callback.html'));
		} catch (error) {
			return this.renderCallbackError(
				res,
				(error as Error).message,
				// eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
				'body' in error ? jsonStringify(error.body) : undefined,
			);
		}
	}

	private renderCallbackError(res: Response, message: string, reason?: string) {
		res.render('oauth-error-callback', { error: { message, reason } });
	}
}
