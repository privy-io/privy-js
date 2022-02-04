export class CryptoError extends Error {
  /**
   * Original Error object
   */
  cause?: Error;

  /**
   * @param {string} message - Human-readable message.
   * @param {unknown} cause - Source of this error.
   */
  constructor(message: string, cause?: unknown) {
    super(message);

    if (cause instanceof Error) {
      this.cause = cause;
    }
  }
}
