/**
 * A small sample of secrets that show up constantly in real HS256 JWT
 * breaches — tutorial defaults, framework placeholders, and short obvious
 * strings. This is intentionally not exhaustive (that's what tools like
 * jwt_tool's full wordlist are for); it exists so the workbench can catch
 * the "someone left the example secret in prod" class of bug instantly,
 * client-side, without shipping a multi-megabyte wordlist.
 */
export const COMMON_JWT_SECRETS: readonly string[] = [
  "secret",
  "secretkey",
  "your-256-bit-secret",
  "your-secret-key",
  "changeme",
  "password",
  "12345678",
  "qwertyuiop",
  "jwtsecret",
  "jwt_secret",
  "supersecret",
  "mysecret",
  "shhhhh",
  "s3cr3t",
  "test",
  "development",
  "key",
  "private_key",
  "encryptionkey",
  "0123456789",
];
