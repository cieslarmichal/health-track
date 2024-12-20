import { type Config } from '../../core/config.js';
import { coreSymbols } from '../../core/symbols.js';
import { authSymbols } from '../authModule/symbols.js';
import { UserHttpController } from './api/httpControllers/userHttpController/userHttpController.js';
import { EmailQueueController } from './api/queueControllers/emailQueueController/emailQueueController.js';
import { type ChangeUserPasswordAction } from './application/actions/changeUserPasswordCommandHandler/changeUserPasswordCommandHandler.js';
import { ChangeUserPasswordActionImpl } from './application/actions/changeUserPasswordCommandHandler/changeUserPasswordCommandHandlerImpl.js';
import { type DeleteUserAction } from './application/actions/deleteUserCommandHandler/deleteUserCommandHandler.js';
import { DeleteUserActionImpl } from './application/actions/deleteUserCommandHandler/deleteUserCommandHandlerImpl.js';
import { type FindUserQueryHandler } from './application/actions/findUserQueryHandler/findUserQueryHandler.js';
import { FindUserQueryHandlerImpl } from './application/actions/findUserQueryHandler/findUserQueryHandlerImpl.js';
import { type FindUsersQueryHandler } from './application/actions/findUsersQueryHandler/findUsersQueryHandler.js';
import { FindUsersQueryHandlerImpl } from './application/actions/findUsersQueryHandler/findUsersQueryHandlerImpl.js';
import { type LoginUserAction } from './application/actions/loginUserCommandHandler/loginUserCommandHandler.js';
import { LoginUserActionImpl } from './application/actions/loginUserCommandHandler/loginUserCommandHandlerImpl.js';
import { type LogoutUserAction } from './application/actions/logoutUserCommandHandler/logoutUserCommandHandler.js';
import { LogoutUserActionImpl } from './application/actions/logoutUserCommandHandler/logoutUserCommandHandlerImpl.js';
import { type RefreshUserTokensAction } from './application/actions/refreshUserTokensCommandHandler/refreshUserTokensCommandHandler.js';
import { RefreshUserTokensActionImpl } from './application/actions/refreshUserTokensCommandHandler/refreshUserTokensCommandHandlerImpl.js';
import { type RegisterUserAction } from './application/actions/registerUserCommandHandler/registerUserCommandHandler.js';
import { RegisterUserActionImpl } from './application/actions/registerUserCommandHandler/registerUserCommandHandlerImpl.js';
import { type SendResetPasswordEmailAction } from './application/actions/sendResetPasswordEmailCommandHandler/sendResetPasswordEmailCommandHandler.js';
import { SendResetPasswordEmailActionImpl } from './application/actions/sendResetPasswordEmailCommandHandler/sendResetPasswordEmailCommandHandlerImpl.js';
import { type SendVerificationEmailAction } from './application/actions/sendVerificationEmailCommandHandler/sendVerificationEmailCommandHandler.js';
import { SendVerificationEmailActionImpl } from './application/actions/sendVerificationEmailCommandHandler/sendVerificationEmailCommandHandlerImpl.js';
import { type UpdateUserAction } from './application/actions/updateUserCommandHandler/updateUserCommandHandler.js';
import { UpdateUserActionImpl } from './application/actions/updateUserCommandHandler/updateUserCommandHandlerImpl.js';
import { type VerifyUserEmailAction } from './application/actions/verifyUserEmailCommandHandler/verifyUserEmailCommandHandler.js';
import { VerifyUserEmailActionImpl } from './application/actions/verifyUserEmailCommandHandler/verifyUserEmailCommandHandlerImpl.js';
import { type EmailMessageBus } from './application/messageBuses/emailMessageBus/emailMessageBus.js';
import { type HashService } from './application/services/hashService/hashService.js';
import { HashServiceImpl } from './application/services/hashService/hashServiceImpl.js';
import { type PasswordValidationService } from './application/services/passwordValidationService/passwordValidationService.js';
import { PasswordValidationServiceImpl } from './application/services/passwordValidationService/passwordValidationServiceImpl.js';
import { type BlacklistTokenRepository } from './domain/repositories/blacklistTokenRepository/blacklistTokenRepository.js';
import { type EmailEventRepository } from './domain/repositories/emailEventRepository/emailEventRepository.js';
import { type UserRepository } from './domain/repositories/userRepository/userRepository.js';
import { EmailMessageBusImpl } from './infrastructure/messageBuses/emailMessageBus/emailMessageBusImpl.js';
import { symbols } from './symbols.js';
import { type DatabaseClient } from '../../libs/database/databaseClient.js';
import { type DependencyInjectionContainer } from '../../libs/dependencyInjection/dependencyInjectionContainer.js';
import { type DependencyInjectionModule } from '../../libs/dependencyInjection/dependencyInjectionModule.js';
import { type LoggerService } from '../../libs/logger/loggerService.js';
import { type SendGridService } from '../../libs/sendGrid/sendGridService.js';
import { type BlacklistTokenMapper } from './infrastructure/repositories/blacklistTokenRepository/blacklistTokenMapper/blacklistTokenMapper.js';
import { BlacklistTokenMapperImpl } from './infrastructure/repositories/blacklistTokenRepository/blacklistTokenMapper/blacklistTokenMapperImpl.js';
import { BlacklistTokenRepositoryImpl } from './infrastructure/repositories/blacklistTokenRepository/blacklistTokenRepositoryImpl.js';
import { EmailEventRepositoryImpl } from './infrastructure/repositories/emailEventRepository/emailEventRepositoryImpl.js';
import { EmailEventMapper } from './infrastructure/repositories/emailEventRepository/mappers/emailEventMapper/emailEventMapper.js';
import { type UserMapper } from './infrastructure/repositories/userRepository/userMapper/userMapper.js';
import { UserMapperImpl } from './infrastructure/repositories/userRepository/userMapper/userMapperImpl.js';
import { UserRepositoryImpl } from './infrastructure/repositories/userRepository/userRepositoryImpl.js';
import { type UuidService } from '../../libs/uuid/uuidService.js';
import { type AccessControlService } from '../authModule/application/services/accessControlService/accessControlService.js';
import { type TokenService } from '../authModule/application/services/tokenService/tokenService.js';

export class UserModule implements DependencyInjectionModule {
  public declareBindings(container: DependencyInjectionContainer): void {
    container.bind<UserMapper>(symbols.userMapper, () => new UserMapperImpl());

    container.bind<UserRepository>(
      symbols.userRepository,
      () =>
        new UserRepositoryImpl(
          container.get<DatabaseClient>(coreSymbols.databaseClient),
          container.get<UserMapper>(symbols.userMapper),
          container.get<UuidService>(coreSymbols.uuidService),
        ),
    );

    container.bind<BlacklistTokenMapper>(symbols.blacklistTokenMapper, () => new BlacklistTokenMapperImpl());

    container.bind<BlacklistTokenRepository>(
      symbols.blacklistTokenRepository,
      () =>
        new BlacklistTokenRepositoryImpl(
          container.get<DatabaseClient>(coreSymbols.databaseClient),
          container.get<BlacklistTokenMapper>(symbols.blacklistTokenMapper),
          container.get<UuidService>(coreSymbols.uuidService),
        ),
    );

    container.bind<HashService>(
      symbols.hashService,
      () => new HashServiceImpl(container.get<Config>(coreSymbols.config)),
    );

    container.bind<PasswordValidationService>(
      symbols.passwordValidationService,
      () => new PasswordValidationServiceImpl(),
    );

    container.bind<RegisterUserAction>(
      symbols.registerUserAction,
      () =>
        new RegisterUserActionImpl(
          container.get<UserRepository>(symbols.userRepository),
          container.get<HashService>(symbols.hashService),
          container.get<LoggerService>(coreSymbols.loggerService),
          container.get<PasswordValidationService>(symbols.passwordValidationService),
          container.get<SendVerificationEmailAction>(symbols.sendVerificationEmailAction),
        ),
    );

    container.bind<LoginUserAction>(
      symbols.loginUserAction,
      () =>
        new LoginUserActionImpl(
          container.get<UserRepository>(symbols.userRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
          container.get<HashService>(symbols.hashService),
          container.get<TokenService>(authSymbols.tokenService),
          container.get<Config>(coreSymbols.config),
        ),
    );

    container.bind<LogoutUserAction>(
      symbols.logoutUserAction,
      () =>
        new LogoutUserActionImpl(
          container.get<UserRepository>(symbols.userRepository),
          container.get<TokenService>(authSymbols.tokenService),
          container.get<BlacklistTokenRepository>(symbols.blacklistTokenRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
        ),
    );

    container.bind<RefreshUserTokensAction>(
      symbols.refreshUserTokensAction,
      () =>
        new RefreshUserTokensActionImpl(
          container.get<LoggerService>(coreSymbols.loggerService),
          container.get<TokenService>(authSymbols.tokenService),
          container.get<Config>(coreSymbols.config),
          container.get<UserRepository>(symbols.userRepository),
          container.get<BlacklistTokenRepository>(symbols.blacklistTokenRepository),
        ),
    );

    container.bind<SendResetPasswordEmailAction>(
      symbols.sendResetPasswordEmailAction,
      () =>
        new SendResetPasswordEmailActionImpl(
          container.get<TokenService>(authSymbols.tokenService),
          container.get<UserRepository>(symbols.userRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
          container.get<Config>(coreSymbols.config),
          container.get<EmailMessageBus>(symbols.emailMessageBus),
        ),
    );

    container.bind<ChangeUserPasswordAction>(
      symbols.changeUserPasswordAction,
      () =>
        new ChangeUserPasswordActionImpl(
          container.get<UserRepository>(symbols.userRepository),
          container.get<BlacklistTokenRepository>(symbols.blacklistTokenRepository),
          container.get<HashService>(symbols.hashService),
          container.get<TokenService>(authSymbols.tokenService),
          container.get<PasswordValidationService>(symbols.passwordValidationService),
          container.get<LoggerService>(coreSymbols.loggerService),
        ),
    );

    container.bind<DeleteUserAction>(
      symbols.deleteUserAction,
      () =>
        new DeleteUserActionImpl(
          container.get<UserRepository>(symbols.userRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
        ),
    );

    container.bind<UpdateUserAction>(
      symbols.updateUserAction,
      () =>
        new UpdateUserActionImpl(
          container.get<UserRepository>(symbols.userRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
        ),
    );

    container.bind<FindUserQueryHandler>(
      symbols.findUserQueryHandler,
      () => new FindUserQueryHandlerImpl(container.get<UserRepository>(symbols.userRepository)),
    );

    container.bind<FindUsersQueryHandler>(
      symbols.findUsersQueryHandler,
      () => new FindUsersQueryHandlerImpl(container.get<UserRepository>(symbols.userRepository)),
    );

    container.bind<SendVerificationEmailAction>(
      symbols.sendVerificationEmailAction,
      () =>
        new SendVerificationEmailActionImpl(
          container.get<TokenService>(authSymbols.tokenService),
          container.get<UserRepository>(symbols.userRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
          container.get<Config>(coreSymbols.config),
          container.get<EmailMessageBus>(symbols.emailMessageBus),
        ),
    );

    container.bind<VerifyUserEmailAction>(
      symbols.verifyUserEmailAction,
      () =>
        new VerifyUserEmailActionImpl(
          container.get<TokenService>(authSymbols.tokenService),
          container.get<UserRepository>(symbols.userRepository),
          container.get<LoggerService>(coreSymbols.loggerService),
        ),
    );

    container.bind<UserHttpController>(
      symbols.userHttpController,
      () =>
        new UserHttpController(
          container.get<RegisterUserAction>(symbols.registerUserAction),
          container.get<LoginUserAction>(symbols.loginUserAction),
          container.get<DeleteUserAction>(symbols.deleteUserAction),
          container.get<UpdateUserAction>(symbols.updateUserAction),
          container.get<FindUserQueryHandler>(symbols.findUserQueryHandler),
          container.get<AccessControlService>(authSymbols.accessControlService),
          container.get<VerifyUserEmailAction>(symbols.verifyUserEmailAction),
          container.get<SendResetPasswordEmailAction>(symbols.sendResetPasswordEmailAction),
          container.get<ChangeUserPasswordAction>(symbols.changeUserPasswordAction),
          container.get<LogoutUserAction>(symbols.logoutUserAction),
          container.get<RefreshUserTokensAction>(symbols.refreshUserTokensAction),
          container.get<SendVerificationEmailAction>(symbols.sendVerificationEmailAction),
        ),
    );

    container.bind<EmailEventMapper>(symbols.emailEventMapper, () => new EmailEventMapper());

    container.bind<EmailEventRepository>(
      symbols.emailEventRepository,
      () =>
        new EmailEventRepositoryImpl(
          container.get<DatabaseClient>(coreSymbols.databaseClient),
          container.get<UuidService>(coreSymbols.uuidService),
          container.get<EmailEventMapper>(symbols.emailEventMapper),
        ),
    );

    container.bind<EmailMessageBus>(
      symbols.emailMessageBus,
      () => new EmailMessageBusImpl(container.get<EmailEventRepository>(symbols.emailEventRepository)),
    );

    container.bind<EmailQueueController>(
      symbols.emailQueueController,
      () =>
        new EmailQueueController(
          container.get<EmailEventRepository>(symbols.emailEventRepository),
          container.get<SendGridService>(coreSymbols.sendGridService),
          container.get<LoggerService>(coreSymbols.loggerService),
        ),
    );
  }
}
