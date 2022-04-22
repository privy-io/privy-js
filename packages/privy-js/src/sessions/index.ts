export interface Session {
  token: string | null;
  isAuthenticated(): Promise<boolean>;
  authenticate(): Promise<void>;
  destroy(): Promise<void>;
}
