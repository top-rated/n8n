import { mock } from 'jest-mock-extended';
import { BadRequestError } from '@/ResponseHelper';
import { NodeTypesController } from '@/controllers/nodeTypes.controller';
import type { NodeTypes } from '@/NodeTypes';
import type { NodeTypesRequest } from '@/requests';

describe('NodeTypesController', () => {
	const nodeTypes = mock<NodeTypes>();
	const controller = new NodeTypesController(mock(), nodeTypes);

	describe('getMappingFields', () => {
		it('should throw a BadRequestError if parameters are missing', async () => {
			const req1 = mock<NodeTypesRequest.GetMappingFields>({ query: { nodeTypeAndVersion: '' } });
			expect(controller.getMappingFields(req1)).rejects.toThrowError(
				new BadRequestError('Parameter nodeTypeAndVersion is required.'),
			);

			const req2 = mock<NodeTypesRequest.GetMappingFields>({
				query: { nodeTypeAndVersion: '{}', currentNodeParameters: '' },
			});
			expect(controller.getMappingFields(req2)).rejects.toThrowError(
				new BadRequestError('Parameter currentNodeParameters is required.'),
			);
		});
	});
});
