export const symbols = {
  blacklistTokenMapper: Symbol('blacklistTokenMapper'),
  blacklistTokenRepository: Symbol('blacklistTokenRepository'),

  userMapper: Symbol('userMapper'),
  userRepository: Symbol('userRepository'),
  registerUserAction: Symbol('registerUserAction'),
  findUserQueryHandler: Symbol('findUserQueryHandler'),
  findUsersQueryHandler: Symbol('findUsersQueryHandler'),
  loginUserAction: Symbol('loginUserAction'),
  refreshUserTokensAction: Symbol('refreshUserTokensAction'),
  logoutUserAction: Symbol('logoutUserAction'),
  deleteUserAction: Symbol('deleteUserAction'),
  updateUserAction: Symbol('updateUserAction'),
  sendResetPasswordEmailAction: Symbol('sendResetPasswordEmailAction'),
  sendVerificationEmailAction: Symbol('sendVerificationEmailAction'),
  changeUserPasswordAction: Symbol('changeUserPasswordAction'),
  verifyUserEmailAction: Symbol('verifyUserEmailAction'),
  userHttpController: Symbol('userHttpController'),

  emailEventRepository: Symbol('emailEventRepository'),
  emailEventMapper: Symbol('emailEventMapper'),
  emailMessageBus: Symbol('emailMessageBus'),
  emailQueueController: Symbol('emailQueueController'),

  hashService: Symbol('hashService'),
  passwordValidationService: Symbol('passwordValidationService'),
};

export const userSymbols = {
  userHttpController: symbols.userHttpController,
  userRepository: symbols.userRepository,
  emailQueueController: symbols.emailQueueController,
  hashService: symbols.hashService,
};
