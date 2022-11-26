import * as crypto from 'crypto';
import * as sjcl from 'sjcl';
import { IStringEncryption } from '../interfaces';
import * as base64js from 'base64-js';

export default class StringEncryption {
  key: string;

  // @sjcl-algorithm
  BITS_PER_WORD: number = 32;

  ALGORITHM_NONCE_SIZE: number = 3;

  ALGORITHM_KEY_SIZE: number = 4;

  PBKDF2_SALT_SIZE: number = 4; // 32-bit words.

  PBKDF2_ITERATIONS: number = 32767;

  BEND_SIZE: number = 3;
  // @scee-algorithm
  SCEE_ALGORITHM_NAME: string = "AES-GCM";

  SCEE_ALGORITHM_NONCE_SIZE: number = 12;

  SCEE_ALGORITHM_KEY_SIZE: number = 16 * 8;

  SCEE_PBKDF2_SALT_SIZE: number = 16;

  SCEE_PBKDF2_ITERATIONS: number = 32767;

  constructor(params: IStringEncryption) {
    this.key = params.key
    if (Object.keys(params).length > 0) {
      Object.keys(params).map((x: string) => {
        if ((params as {[key in keyof IStringEncryption]: number | string})[x as keyof IStringEncryption]) {
          (this[x as keyof IStringEncryption] as number | string | undefined) = params[x as keyof IStringEncryption]
        }
      })
    }
    if (!params.key) {
      throw new Error("Key is not assigned to constructor")
    }
  }

  createPassword(str: string) {
    return crypto.createHmac('sha256', this.key)
      .update(str)
      .digest('hex')
  }

  encryptString(text: string, password: string) {
    const salt = sjcl.random.randomWords(this.PBKDF2_SALT_SIZE);
    const key = sjcl.misc.pbkdf2(password, salt, this.PBKDF2_ITERATIONS, this.ALGORITHM_NONCE_SIZE * this.BITS_PER_WORD);
    const plainTextRaw = sjcl.codec.utf8String.toBits(text);
    const chiperTextAndNonceAndSalt = sjcl.bitArray.concat(salt, this.encrypt(plainTextRaw, key))
  }

  decryptString(base64CiphertextAndNonceAndSalt: string, password: string) {
    // Decode the base64.
    const ciphertextAndNonceAndSalt = sjcl.codec.base64.toBits(base64CiphertextAndNonceAndSalt);

    // Create buffers of salt and ciphertextAndNonce.
    const salt = sjcl.bitArray.bitSlice(ciphertextAndNonceAndSalt, 0, this.PBKDF2_SALT_SIZE * this.BITS_PER_WORD);
    const ciphertextAndNonce = sjcl.bitArray.bitSlice(ciphertextAndNonceAndSalt, this.PBKDF2_SALT_SIZE * this.BITS_PER_WORD, this.BEND_SIZE);

    // Derive the key using PBKDF2.
    const key = sjcl.misc.pbkdf2(password, salt, this.PBKDF2_ITERATIONS, this.ALGORITHM_KEY_SIZE * this.BITS_PER_WORD);
    
    // Decrypt and return result.
    return sjcl.codec.utf8String.fromBits(this.decrypt(ciphertextAndNonce, key));
  }

  encrypt(plaintext: sjcl.BitArray, key: sjcl.BitArray) {
    // Generate a 96-bit nonce using a CSPRNG.
    const nonce = sjcl.random.randomWords(this.ALGORITHM_NONCE_SIZE);
    // Encrypt and prepend nonce.
    const ciphertext = sjcl.mode.gcm.encrypt(new sjcl.cipher.aes(key), plaintext, nonce);
    return sjcl.bitArray.concat(nonce, ciphertext);
  }

  decrypt(ciphertextAndNonce: sjcl.BitArray, key: sjcl.BitArray) {
    // Create buffers of nonce and ciphertext.
    const nonce = sjcl.bitArray.bitSlice(ciphertextAndNonce, 0, this.ALGORITHM_NONCE_SIZE * this.BITS_PER_WORD);
    const ciphertext = sjcl.bitArray.bitSlice(ciphertextAndNonce, this.ALGORITHM_NONCE_SIZE * this.BITS_PER_WORD, this.BEND_SIZE);

    // Decrypt and return result.
    return sjcl.mode.gcm.decrypt(new sjcl.cipher.aes(key), ciphertext, nonce);
  }

  async encryptSceeString(plaintext: string, password: string = this.key) {
    // Generate a 128-bit salt using a CSPRNG and a nonce.
    let salt = crypto.getRandomValues(new Uint8Array(this.SCEE_PBKDF2_SALT_SIZE));
    let nonce = crypto.getRandomValues(new Uint8Array(this.SCEE_ALGORITHM_NONCE_SIZE));
    let aesGcm = { name: this.SCEE_ALGORITHM_NAME, iv: nonce };
  
    // Derive a key using PBKDF2.
    let deriveParams = { name: "PBKDF2", salt: salt, iterations: this.SCEE_PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
    let rawKey = await crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]);
    let cryptoKey = await crypto.subtle.deriveKey(deriveParams, rawKey, { name: this.SCEE_ALGORITHM_NAME, length: this.SCEE_ALGORITHM_KEY_SIZE }, true, ["encrypt"]);
  
    // Encrypt the string.
    let ciphertext = await this.encryptWithCryptoKey(aesGcm, (new TextEncoder()).encode(plaintext), cryptoKey);
    return base64js.fromByteArray(this.joinBuffers(salt, ciphertext));
  }

  async decryptSceeString(base64ChiperTextAndSalt: string, password: string) {
  // Decode the base64.
	const ciphertextAndNonceAndSalt = base64js.toByteArray(base64ChiperTextAndSalt);

	// Create buffers of salt and ciphertextAndNonce.
	const salt = ciphertextAndNonceAndSalt.slice(0, this.SCEE_PBKDF2_SALT_SIZE);
	const nonce = ciphertextAndNonceAndSalt.slice(this.SCEE_PBKDF2_SALT_SIZE, this.SCEE_PBKDF2_SALT_SIZE + this.SCEE_ALGORITHM_NONCE_SIZE);
	const ciphertext = ciphertextAndNonceAndSalt.slice(this.SCEE_PBKDF2_SALT_SIZE + this.SCEE_ALGORITHM_NONCE_SIZE);
	const aesGcm = { name: this.SCEE_ALGORITHM_NAME, iv: nonce };

	// Derive the key using PBKDF2.
	const deriveParams = { name: "PBKDF2", salt: salt, iterations: this.SCEE_PBKDF2_ITERATIONS, hash: { name: "SHA-256" } };
	const rawKey = await crypto.subtle.importKey("raw", (new TextEncoder()).encode(password), { name: "PBKDF2" }, false, ["deriveKey", "deriveBits"]);
	const cryptoKey = await crypto.subtle.deriveKey(deriveParams, rawKey, { name: this.SCEE_ALGORITHM_NAME, length: this.SCEE_ALGORITHM_KEY_SIZE }, true, ["decrypt"]);

	// Decrypt the string.
	const plaintext = await this.decryptWithCryptoKey(aesGcm, ciphertext, cryptoKey);
	return (new TextDecoder()).decode(plaintext);
  }

  async encryptWithCryptoKey(aesGcm: { name: string; iv: Uint8Array }, plaintext: crypto.webcrypto.BufferSource, cryptoKey: crypto.webcrypto.CryptoKey) {
    const ciphertext = await crypto.subtle.encrypt(aesGcm, cryptoKey, plaintext);
    return this.joinBuffers(aesGcm.iv, new Uint8Array(ciphertext));
  }

  joinBuffers(a: Uint8Array, b: Uint8Array) {
    let c = new Uint8Array(a.byteLength + b.byteLength);
    for (let i = 0; i < a.length; i++) {
      c[i] = a[i];
    }
    for (let i = 0; i < b.length; i++) {
      c[i + a.length] = b[i];
    }
    return c;
  }

  async decryptWithCryptoKey(
    aesGcm: crypto.webcrypto.AlgorithmIdentifier | crypto.webcrypto.RsaOaepParams | crypto.webcrypto.AesCtrParams | crypto.webcrypto.AesCbcParams | crypto.webcrypto.AesGcmParams, 
    ciphertext: crypto.webcrypto.BufferSource, 
    cryptoKey: crypto.webcrypto.CryptoKey
  ) {
    const plaintext = await crypto.subtle.decrypt(aesGcm, cryptoKey, ciphertext);
    return new Uint8Array(plaintext);
  }
}