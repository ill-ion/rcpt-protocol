/// <reference lib="es2022" />

declare module "node:crypto" {
  export function createHash(algorithm: string): {
    update(data: Buffer | string): { digest(encoding: "hex"): string; digest(): Buffer };
  };
  export function randomBytes(size: number): Buffer;
  export function generateKeyPairSync(
    type: "ed25519"
  ): {
    publicKey: {
      export(options: { type: string; format: string }): Buffer;
    };
    privateKey: {
      export(options: { type: string; format: string; passphrase?: undefined }): Buffer;
    };
  };
  export function sign(
    algorithm: null,
    data: Buffer,
    key: any
  ): Buffer;
  export function verify(
    algorithm: null,
    data: Buffer,
    key: any,
    signature: Buffer
  ): boolean;
  export function createPublicKey(options: {
    key: Buffer;
    format: string;
    type: string;
  } | any): any;
  export function createPrivateKey(options: {
    key: Buffer;
    format: string;
    type: string;
  }): any;
}

declare module "node:test" {
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: () => void | Promise<void>): void;
}

declare module "node:assert/strict" {
  export function ok(value: unknown, message?: string): void;
  export function equal(actual: unknown, expected: unknown, message?: string): void;
  export function notEqual(actual: unknown, expected: unknown, message?: string): void;
  export function deepEqual(actual: unknown, expected: unknown, message?: string): void;
  export function throws(fn: () => void, pattern?: RegExp | Error): void;
}

interface Buffer extends Uint8Array {
  toString(encoding?: string): string;
  subarray(begin?: number, end?: number): Buffer;
}

interface BufferConstructor {
  from(data: string | ArrayBuffer | number[], encoding?: string): Buffer;
  from(data: Buffer): Buffer;
  concat(buffers: Buffer[]): Buffer;
  alloc(size: number): Buffer;
  isBuffer(obj: unknown): obj is Buffer;
}

declare const Buffer: BufferConstructor;
