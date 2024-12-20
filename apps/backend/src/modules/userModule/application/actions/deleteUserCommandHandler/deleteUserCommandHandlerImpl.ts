import { type DeleteUserAction, type DeleteUserActionPayload } from './deleteUserAction.js';
import { ResourceNotFoundError } from '../../../../../common/errors/resourceNotFoundError.js';
import { type LoggerService } from '../../../../../libs/logger/services/loggerService/loggerService.js';
import { type UserRepository } from '../../../domain/repositories/userRepository/userRepository.js';

export class DeleteUserActionImpl implements DeleteUserAction {
  public constructor(
    private readonly userRepository: UserRepository,
    private readonly loggerService: LoggerService,
  ) {}

  public async execute(payload: DeleteUserActionPayload): Promise<void> {
    const { userId } = payload;

    this.loggerService.debug({
      message: 'Deleting User...',
      userId,
    });

    const existingUser = await this.userRepository.findUser({ id: userId });

    if (!existingUser) {
      throw new ResourceNotFoundError({
        resource: 'User',
        userId,
      });
    }

    await this.userRepository.deleteUser({ id: userId });

    this.loggerService.debug({
      message: 'User deleted.',
      userId,
    });
  }
}
