import { type Action } from '../../../../../common/types/commandHandler.js';

export interface LoginUserActionPayload {
  readonly email: string;
  readonly password: string;
}

export interface LoginUserActionResult {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly accessTokenExpiresIn: number;
}

export type LoginUserAction = Action<LoginUserActionPayload, LoginUserActionResult>;
