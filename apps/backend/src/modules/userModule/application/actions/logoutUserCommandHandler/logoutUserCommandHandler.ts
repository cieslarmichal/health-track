import { type Action } from '../../../../../common/types/commandHandler.js';

export interface ExecutePayload {
  readonly userId: string;
  readonly refreshToken: string;
  readonly accessToken: string;
}

export type LogoutUserAction = Action<ExecutePayload, void>;
