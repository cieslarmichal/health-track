import { type Static, Type } from '@sinclair/typebox';

import type { RefreshUserTokensRequestBody, RefreshUserTokensResponseBody } from '@common/contracts';

import { type TypeExtends } from '../../../../../../libs/types/schemaExtends.js';

export const refreshUserTokensBodyDtoSchema = Type.Object({
  refreshToken: Type.String({ minLength: 1 }),
});

export type RefreshUserTokensBodyDto = TypeExtends<
  Static<typeof refreshUserTokensBodyDtoSchema>,
  RefreshUserTokensRequestBody
>;

export const refreshUserTokensResponseBodyDtoSchema = Type.Object({
  accessToken: Type.String(),
  refreshToken: Type.String(),
  expiresIn: Type.Number(),
});

export type RefreshUserTokensResponseBodyDto = TypeExtends<
  Static<typeof refreshUserTokensResponseBodyDtoSchema>,
  RefreshUserTokensResponseBody
>;
