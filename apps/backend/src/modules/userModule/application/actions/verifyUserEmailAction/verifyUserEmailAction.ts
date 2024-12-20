import { type Action } from '../../../../../common/types/commandHandler.js';

export interface ExecutePayload {
  readonly emailVerificationToken: string;
}

export type VerifyUserEmailAction = Action<ExecutePayload, void>;
