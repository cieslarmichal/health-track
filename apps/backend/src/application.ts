import { ApplicationHttpController } from './api/httpControllers/applicationHttpController/applicationHttpController.js';
import { type Config, ConfigFactory } from './config.js';
import { HttpServer } from './httpServer.js';
import { type LoggerService } from './libs/logger/loggerService.js';
import { LoggerServiceFactory } from './libs/logger/loggerServiceFactory.js';
import { S3ClientFactory } from './libs/s3/s3ClientFactory.js';
import { S3Service } from './libs/s3/s3Service.js';
import { UuidService } from './libs/uuid/uuidService.js';

export class Application {
  private readonly config: Config;
  private readonly logger: LoggerService;
  private httpServer: HttpServer | undefined;

  public constructor() {
    this.config = ConfigFactory.create();

    this.logger = LoggerServiceFactory.create({
      logLevel: this.config.logLevel,
    });
  }

  public async start(): Promise<void> {
    const uuidService = new UuidService();

    const s3Service = new S3Service(S3ClientFactory.create(this.config.aws));

    console.log({ uuidService, s3Service });

    const applicationHttpController = new ApplicationHttpController();

    this.httpServer = new HttpServer([applicationHttpController], this.logger, this.config);

    await this.httpServer.start();
  }

  public async stop(): Promise<void> {
    await this.httpServer?.stop();
  }
}
