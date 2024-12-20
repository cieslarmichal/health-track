import { type Static, Type } from '@sinclair/typebox';

import type * as contracts from '@common/contracts';

import { userDtoSchema } from './userDto.js';
import { type TypeExtends } from '../../../../../../libs/types/schemaExtends.js';

export const updateUserPathParamsDtoSchema = Type.Object({
  userId: Type.String({ format: 'uuid' }),
});

export type UpdateUserPathParamsDto = TypeExtends<
  Static<typeof updateUserPathParamsDtoSchema>,
  contracts.UpdateUserPathParams
>;

export const updateUserRequestBodyDtoSchema = Type.Object({
  name: Type.String({
    minLength: 1,
    maxLength: 64,
  }),
});

export type UpdateUserRequestBodyDto = TypeExtends<
  Static<typeof updateUserRequestBodyDtoSchema>,
  contracts.UpdateUserRequestBody
>;

export const updateUserResponseBodyDtoSchema = userDtoSchema;

export type UpdateUserResponseBodyDto = TypeExtends<
  Static<typeof updateUserResponseBodyDtoSchema>,
  contracts.UpdateUserResponseBody
>;
