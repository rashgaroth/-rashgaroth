export interface IObjectEncryption {
  key: string
  matcher?: string
}

export interface IStringEncryption {
  key: string;
  BITS_PER_WORD?: number;
  ALGORITHM_NONCE_SIZE?: number;
  ALGORITHM_KEY_SIZE?: number;
  PBKDF2_SALT_SIZE?: number; // 32-bit words.
  PBKDF2_ITERATIONS?: number;
  BEND_SIZE?: number;
  SCEE_ALGORITHM_NAME?: string;
  SCEE_ALGORITHM_NONCE_SIZE?: number;
  SCEE_ALGORITHM_KEY_SIZE?: number;
  SCEE_PBKDF2_SALT_SIZE?: number;
  SCEE_PBKDF2_ITERATIONS?: number;
}