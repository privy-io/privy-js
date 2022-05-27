import axios from 'axios';

export abstract class PrivyError extends Error {
  /**
   * Privy error type.
   */
  abstract type: string;

  /**
   * Original Error object, it the error originated client-side.
   */
  cause?: Error;

  /**
   * @param type Privy error type.
   * @param message Human-readable message.
   * @param cause Source of this error.
   */
  protected constructor(message: string, cause?: unknown) {
    super(message);

    if (cause instanceof Error) {
      this.cause = cause;
    }
  }

  public toString(): string {
    return `${this.type}: ${this.message}`;
  }
}

/**
 * Issues with the Privy api.
 */
export class PrivyApiError extends PrivyError {
  /**
   * HTTP status code, or `null` if no response was received.
   */
  public status: number | null;

  constructor(public type: string, status: number | null, message: string, cause?: unknown) {
    super(message, cause);
    this.status = status;
  }
}

/**
 * Issues with the Privy client.
 */
export class PrivyClientError extends PrivyError {
  type = 'client_error';

  constructor(message: string, cause?: unknown) {
    super(message, cause);
  }
}

export const wrapApiError = (error: unknown): unknown => {
  if (!axios.isAxiosError(error)) {
    return formatPrivyError(error);
  }

  if (!error.response) {
    // The request was made but no response was received, or another connection error occurred.
    return new PrivyApiError('api_error', null, error.message, error);
  }

  // The request was made and the server responded with a 4xx/5xx status code.
  // Convert to a wrapped PrivyError.
  const {type, message} = error.response.data;
  return new PrivyApiError(type, error.response.status, message, error);
};

export const formatPrivyError = (error: unknown): PrivyError => {
  if (error instanceof PrivyError) {
    // Pass through PrivyError objects.
    return error;
  }

  if (error instanceof Error) {
    // Non-Privy error occurred. Wrap it in a PrivyClientError.
    return new PrivyClientError(error.message, error);
  }

  return new PrivyClientError(`Internal error: ${error}`);
};
