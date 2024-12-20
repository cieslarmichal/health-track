export function serializeError(error: unknown): Record<string, unknown> {
  const serializedError: Record<string, unknown> = {};

  if (error instanceof Error) {
    for (const key of Object.getOwnPropertyNames(error)) {
      const value = Reflect.get(error, key);

      serializedError[key] = value instanceof Error ? serializeError(value) : value;
    }

    return serializedError;
  } else {
    return { error };
  }
}
