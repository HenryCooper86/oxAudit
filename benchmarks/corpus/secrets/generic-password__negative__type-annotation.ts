// A type declaration names a field; it does not carry a value.
export interface Credentials {
  username: string;
  password: string;
  clientSecret: string | null;
}

export type PasswordPolicy = {
  minimumLength: number;
  requiresSymbol: boolean;
};
