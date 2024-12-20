import { UserDatabaseMigrationSource } from './userDatabaseMigrationSource.js';
import { coreSymbols } from '../../../../../core/symbols.js';
import { type DatabaseClient } from '../../../../../libs/database/databaseClient.js';
import { type DependencyInjectionContainer } from '../../../../../libs/dependencyInjection/dependencyInjectionContainer.js';

export class UserDatabaseManager {
  public static async bootstrapDatabase(container: DependencyInjectionContainer): Promise<void> {
    const databaseClient = container.get<DatabaseClient>(coreSymbols.databaseClient);

    const migrationSource = new UserDatabaseMigrationSource();

    await databaseClient.migrate.latest({
      migrationSource,
      tableName: migrationSource.getMigrationTableName(),
    });
  }

  public static async teardownDatabase(container: DependencyInjectionContainer): Promise<void> {
    const databaseClient = container.get<DatabaseClient>(coreSymbols.databaseClient);

    const migrationSource = new UserDatabaseMigrationSource();

    await databaseClient.migrate.rollback({
      migrationSource,
      tableName: migrationSource.getMigrationTableName(),
    });
  }
}
