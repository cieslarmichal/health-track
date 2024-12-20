import { beforeEach, afterEach, expect, it, describe } from 'vitest';

import { BookshelfType, UserRole } from '@common/contracts';

import { type RegisterUserAction } from './registerUserAction.js';
import { testSymbols } from '../../../../../../tests/symbols.js';
import { TestContainer } from '../../../../../../tests/testContainer.js';
import { OperationNotValidError } from '../../../../../common/errors/operationNotValidError.js';
import { ResourceAlreadyExistsError } from '../../../../../common/errors/resourceAlreadyExistsError.js';
import { coreSymbols } from '../../../../../core/symbols.js';
import { type DatabaseClient } from '../../../../../libs/database/clients/databaseClient/databaseClient.js';
import { type BookshelfTestUtils } from '../../../../bookshelfModule/tests/utils/bookshelfTestUtils/bookshelfTestUtils.js';
import { symbols } from '../../../symbols.js';
import { UserTestFactory } from '../../../tests/factories/userTestFactory/userTestFactory.js';
import { type UserTestUtils } from '../../../tests/utils/userTestUtils/userTestUtils.js';

describe('RegisterUserAction', () => {
  let registerUserAction: RegisterUserAction;

  let databaseClient: DatabaseClient;

  let userTestUtils: UserTestUtils;

  let bookshelfTestUtils: BookshelfTestUtils;

  const userTestFactory = new UserTestFactory();

  beforeEach(async () => {
    const container = TestContainer.create();

    registerUserAction = container.get<RegisterUserAction>(symbols.registerUserAction);

    databaseClient = container.get<DatabaseClient>(coreSymbols.databaseClient);

    userTestUtils = container.get<UserTestUtils>(testSymbols.userTestUtils);

    bookshelfTestUtils = container.get<BookshelfTestUtils>(testSymbols.bookshelfTestUtils);

    await userTestUtils.truncate();

    await bookshelfTestUtils.truncate();
  });

  afterEach(async () => {
    await userTestUtils.truncate();

    await bookshelfTestUtils.truncate();

    await databaseClient.destroy();
  });

  it('creates a User and creates bookshelves', async () => {
    const user = userTestFactory.create();

    const { user: createdUser } = await registerUserAction.execute({
      email: user.getEmail(),
      password: user.getPassword(),
      name: user.getName(),
    });

    const foundUser = await userTestUtils.findByEmail({ email: user.getEmail() });

    expect(createdUser.getEmail()).toEqual(user.getEmail());

    expect(createdUser.getIsEmailVerified()).toEqual(false);

    expect(foundUser?.email).toEqual(user.getEmail());

    expect(foundUser?.role).toEqual(UserRole.user);

    const bookshelves = await bookshelfTestUtils.findByUserId({ userId: createdUser.getId() });

    expect(bookshelves).toHaveLength(2);

    const archiveBookshelf = bookshelves.find((bookshelf) => bookshelf.type === BookshelfType.archive);

    expect(archiveBookshelf?.name).toEqual('Archiwum');

    const borrowingBookshelf = bookshelves.find((bookshelf) => bookshelf.type === BookshelfType.borrowing);

    expect(borrowingBookshelf?.name).toEqual('Wypożyczalnia');
  });

  it('throws an error when a User with the same email already exists', async () => {
    const existingUser = await userTestUtils.createAndPersist();

    try {
      await registerUserAction.execute({
        email: existingUser.email,
        password: existingUser.password,
        name: existingUser.name,
      });
    } catch (error) {
      expect(error).toBeInstanceOf(ResourceAlreadyExistsError);

      expect((error as ResourceAlreadyExistsError).context).toEqual({
        resource: 'User',
        email: existingUser.email,
      });

      return;
    }

    expect.fail();
  });

  it('throws an error when password does not meet requirements', async () => {
    const user = userTestFactory.create();

    try {
      await registerUserAction.execute({
        email: user.getEmail(),
        password: '123',
        name: user.getName(),
      });
    } catch (error) {
      expect(error).toBeInstanceOf(OperationNotValidError);

      return;
    }

    expect.fail();
  });
});