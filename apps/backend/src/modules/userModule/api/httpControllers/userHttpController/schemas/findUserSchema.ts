import { type Static, Type } from '@sinclair/typebox';

import type * as contracts from '@common/contracts';

import { type TypeExtends } from '../../../../../../common/types/schemaExtends.js';
import { userDtoSchema } from './userDto.js';

export const findUserPathParamsDtoSchema = Type.Object({
  userId: Type.String({ format: 'uuid' }),
});

export type FindUserPathParamsDto = TypeExtends<
  Static<typeof findUserPathParamsDtoSchema>,
  contracts.FindUserPathParams
>;

export const findUserResponseBodyDtoSchema = userDtoSchema;

export type FindUserResponseBodyDto = TypeExtends<
  Static<typeof findUserResponseBodyDtoSchema>,
  contracts.FindUserResponseBody
>;
