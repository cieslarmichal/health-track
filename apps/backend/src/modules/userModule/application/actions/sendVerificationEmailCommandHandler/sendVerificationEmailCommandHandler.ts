import { type Action } from '../../../../../common/types/commandHandler.js';

export interface ExecutePayload {
  readonly email: string;
}

export type SendVerificationEmailAction = Action<ExecutePayload, void>;
