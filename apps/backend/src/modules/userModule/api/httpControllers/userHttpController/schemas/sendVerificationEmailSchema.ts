import { type Static, Type } from '@sinclair/typebox';

import type * as contracts from '@common/contracts';

import { emailSchema } from './userDto.js';
import { type TypeExtends } from '../../../../../../libs/types/schemaExtends.js';

export const sendVerificationEmailBodyDtoSchema = Type.Object({
  email: emailSchema,
});

export type SendVerificationEmailBodyDto = TypeExtends<
  Static<typeof sendVerificationEmailBodyDtoSchema>,
  contracts.SendVerificationEmailRequestBody
>;

export const sendVerificationEmailResponseBodyDtoSchema = Type.Null();

export type SendVerificationEmailResponseBodyDto = Static<typeof sendVerificationEmailResponseBodyDtoSchema>;
