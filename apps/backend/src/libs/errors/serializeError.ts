export function serializeError(error: unknown): Record<string, unknown> {
  if (error instanceof Error) {
    const serializedError: Record<string, unknown> = {};

    for (const key of Object.getOwnPropertyNames(error)) {
      const value = Reflect.get(error, key);

      serializedError[key] = value instanceof Error ? serializeError(value) : value;
    }

    return serializedError;
  }

  return error as Record<string, unknown>;
}
