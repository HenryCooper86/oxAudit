export interface RequestToken {
  generation: number;
}

export type LatestRequestResult<T> =
  | { current: true; value: T }
  | { current: false };

/**
 * Provides latest-request-wins guards plus a serialized lane for side effects
 * that cannot safely overlap (for example, changing native runtime context).
 */
export class LatestRequestQueue {
  private generation = 0;
  private tail: Promise<void> = Promise.resolve();

  begin(): RequestToken {
    this.generation += 1;
    return { generation: this.generation };
  }

  capture(): RequestToken {
    return { generation: this.generation };
  }

  isCurrent(token: RequestToken): boolean {
    return token.generation === this.generation;
  }

  invalidate(): void {
    this.generation += 1;
  }

  run<T>(
    token: RequestToken,
    operation: () => Promise<T>,
  ): Promise<LatestRequestResult<T>> {
    const execute = async (): Promise<LatestRequestResult<T>> => {
      if (!this.isCurrent(token)) return { current: false };
      const value = await operation();
      return this.isCurrent(token)
        ? { current: true, value }
        : { current: false };
    };
    const result = this.tail.then(execute, execute);
    this.tail = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }
}
