export class RunEffectOnce {
  private fn: () => Promise<void>;
  private promise: Promise<void> | null = null;

  constructor(fn: () => Promise<void>) {
    this.fn = fn;
  }

  execute(): Promise<void> {
    if (this.promise === null) {
      this.promise = (async () => {
        try {
          await this.fn();
        } finally {
          this.promise = null;
        }
      })();
    }

    return this.promise;
  }
}
