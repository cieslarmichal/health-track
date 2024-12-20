import { type Action } from '../../../../../common/types/commandHandler.js';

export interface DeleteUserActionPayload {
  readonly userId: string;
}

export type DeleteUserAction = Action<DeleteUserActionPayload, void>;
