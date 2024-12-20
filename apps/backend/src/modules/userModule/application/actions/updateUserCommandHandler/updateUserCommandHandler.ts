import { type Action } from '../../../../../common/types/commandHandler.js';
import { type User } from '../../../domain/entities/user/user.js';

export interface UpdateUserActionPayload {
  readonly id: string;
  readonly name: string;
}

export interface UpdateUserActionResult {
  readonly user: User;
}

export type UpdateUserAction = Action<UpdateUserActionPayload, UpdateUserActionResult>;
