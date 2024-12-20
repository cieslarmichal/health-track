/* eslint-disable @typescript-eslint/naming-convention */

import { type Static, Type } from '@sinclair/typebox';
import { type FastifyRequest } from 'fastify';

import type * as contracts from '@common/contracts';

import { userDtoSchema } from './userDto.js';
import { InputNotValidError } from '../../../../../../libs/errors/inputNotValidError.js';
import { type TypeExtends } from '../../../../../../libs/types/schemaExtends.js';

export const registerUserRequestBodyDtoSchema = Type.Object({
  email: Type.String({
    format: 'email',
    maxLength: 254,
  }),
  password: Type.String({
    minLength: 8,
    maxLength: 64,
  }),
  name: Type.String({
    minLength: 1,
    maxLength: 64,
  }),
});

export type RegisterUserRequestBodyDto = TypeExtends<
  Static<typeof registerUserRequestBodyDtoSchema>,
  contracts.RegisterUserRequestBody
>;

export const registerUserResponseBodyDtoSchema = userDtoSchema;

export type RegisterUserResponseBodyDto = TypeExtends<
  Static<typeof registerUserResponseBodyDtoSchema>,
  contracts.RegisterUserResponseBody
>;

export const registerUserBodyPreValidationHook = (
  request: FastifyRequest<{ Body: RegisterUserRequestBodyDto }>,
): void => {
  const { name } = request.body;

  const specialCharacterRegex = /[!@#$%^&*(),.?":{}|<>]/g;

  if (specialCharacterRegex.test(name)) {
    throw new InputNotValidError({
      reason: 'body/name must NOT contain special characters',
      value: name,
    });
  }
};
