import { Service } from 'typedi';
import type { IUserSettings } from 'n8n-workflow';
import type { User } from '@db/entities/User';
import { SharedWorkflowRepository, UserRepository } from '@db/repositories';

@Service()
export class UserService {
	constructor(
		private sharedWorkflowRepository: SharedWorkflowRepository,
		private userRepository: UserRepository,
	) {}

	async getWorkflowOwner(workflowId: string): Promise<User> {
		const sharedWorkflow = await this.sharedWorkflowRepository.findOneOrFail({
			relations: ['user'],
			where: {
				workflowId,
				role: {
					scope: 'workflow',
					name: 'owner',
				},
			},
		});

		return sharedWorkflow.user;
	}

	async updateUserSettings(id: string, userSettings: Partial<IUserSettings>) {
		const { settings: currentSettings } = await this.userRepository.findOneOrFail({
			where: { id },
		});
		return this.userRepository.update(id, { settings: { ...currentSettings, ...userSettings } });
	}
}
