import { Application } from './core/application.js';
import { BaseError } from './libs/errors/baseError.js';

export const finalErrorHandler = async (error: unknown): Promise<void> => {
  let formattedError = error;

  if (error instanceof Error) {
    formattedError = {
      name: error.name,
      message: error.message,
      ...(error instanceof BaseError ? { ...error.context } : undefined),
    };
  }

  console.error(
    JSON.stringify({
      message: 'Application error.',
      context: formattedError,
    }),
  );

  await Application.stop();

  process.exit(1);
};

process.on('unhandledRejection', finalErrorHandler);

process.on('uncaughtException', finalErrorHandler);

process.on('SIGINT', finalErrorHandler);

process.on('SIGTERM', finalErrorHandler);

try {
  await Application.start();
} catch (error) {
  await finalErrorHandler(error);
}
