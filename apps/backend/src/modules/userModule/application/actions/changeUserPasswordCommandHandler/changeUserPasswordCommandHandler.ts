import { type Action } from '../../../../../common/types/commandHandler.js';

export interface ChangeUserPasswordActionPayload {
  readonly newPassword: string;
  readonly identifier:
    | {
        readonly resetPasswordToken: string;
      }
    | {
        readonly userId: string;
      };
}

export type ChangeUserPasswordAction = Action<ChangeUserPasswordActionPayload, void>;
