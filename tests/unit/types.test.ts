/**
 * Types unit tests
 *
 * Tests for FipsCryptoError class and ErrorCodes constants
 */

import { describe, it, expect } from 'vitest';
import { FipsCryptoError, ErrorCodes } from '../../src/index.js';

describe('FipsCryptoError', () => {
  describe('constructor', () => {
    it('creates error with message and code', () => {
      const error = new FipsCryptoError('Test error message', 'TEST_CODE');
      expect(error.message).toBe('Test error message');
      expect(error.code).toBe('TEST_CODE');
    });

    it('has correct name property', () => {
      const error = new FipsCryptoError('Test error', 'TEST');
      expect(error.name).toBe('FipsCryptoError');
    });

    it('is an instance of Error', () => {
      const error = new FipsCryptoError('Test', 'CODE');
      expect(error).toBeInstanceOf(Error);
    });

    it('is an instance of FipsCryptoError', () => {
      const error = new FipsCryptoError('Test', 'CODE');
      expect(error).toBeInstanceOf(FipsCryptoError);
    });

    it('has a stack trace', () => {
      const error = new FipsCryptoError('Test', 'CODE');
      expect(error.stack).toBeDefined();
      expect(typeof error.stack).toBe('string');
    });

    it('code is readonly', () => {
      const error = new FipsCryptoError('Test', 'CODE');
      expect(error.code).toBe('CODE');
      // TypeScript prevents reassignment at compile time
      // Runtime check: the property exists and is string
      expect(typeof error.code).toBe('string');
    });
  });

  describe('usage with try/catch', () => {
    it('can be caught and inspected', () => {
      const throwError = () => {
        throw new FipsCryptoError('Something went wrong', ErrorCodes.INVALID_KEY_LENGTH);
      };

      try {
        throwError();
        expect.fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(FipsCryptoError);
        if (error instanceof FipsCryptoError) {
          expect(error.message).toBe('Something went wrong');
          expect(error.code).toBe('INVALID_KEY_LENGTH');
        }
      }
    });

    it('can be distinguished from regular errors', () => {
      const throwRegularError = () => {
        throw new Error('Regular error');
      };

      const throwFipsError = () => {
        throw new FipsCryptoError('FIPS error', 'FIPS_CODE');
      };

      try {
        throwRegularError();
      } catch (error) {
        expect(error).not.toBeInstanceOf(FipsCryptoError);
      }

      try {
        throwFipsError();
      } catch (error) {
        expect(error).toBeInstanceOf(FipsCryptoError);
      }
    });
  });

  describe('with different error codes', () => {
    it('works with WASM_NOT_INITIALIZED', () => {
      const error = new FipsCryptoError('WASM not loaded', ErrorCodes.WASM_NOT_INITIALIZED);
      expect(error.code).toBe('WASM_NOT_INITIALIZED');
    });

    it('works with INVALID_KEY_LENGTH', () => {
      const error = new FipsCryptoError('Wrong key size', ErrorCodes.INVALID_KEY_LENGTH);
      expect(error.code).toBe('INVALID_KEY_LENGTH');
    });

    it('works with INVALID_CIPHERTEXT_LENGTH', () => {
      const error = new FipsCryptoError('Wrong ciphertext size', ErrorCodes.INVALID_CIPHERTEXT_LENGTH);
      expect(error.code).toBe('INVALID_CIPHERTEXT_LENGTH');
    });

    it('works with INVALID_SIGNATURE_LENGTH', () => {
      const error = new FipsCryptoError('Wrong signature size', ErrorCodes.INVALID_SIGNATURE_LENGTH);
      expect(error.code).toBe('INVALID_SIGNATURE_LENGTH');
    });

    it('works with INVALID_SEED_LENGTH', () => {
      const error = new FipsCryptoError('Wrong seed size', ErrorCodes.INVALID_SEED_LENGTH);
      expect(error.code).toBe('INVALID_SEED_LENGTH');
    });

    it('works with INVALID_CONTEXT_LENGTH', () => {
      const error = new FipsCryptoError('Context too long', ErrorCodes.INVALID_CONTEXT_LENGTH);
      expect(error.code).toBe('INVALID_CONTEXT_LENGTH');
    });
  });
});

describe('ErrorCodes', () => {
  describe('constants', () => {
    it('has WASM_NOT_INITIALIZED', () => {
      expect(ErrorCodes.WASM_NOT_INITIALIZED).toBe('WASM_NOT_INITIALIZED');
    });

    it('has INVALID_KEY_LENGTH', () => {
      expect(ErrorCodes.INVALID_KEY_LENGTH).toBe('INVALID_KEY_LENGTH');
    });

    it('has INVALID_CIPHERTEXT_LENGTH', () => {
      expect(ErrorCodes.INVALID_CIPHERTEXT_LENGTH).toBe('INVALID_CIPHERTEXT_LENGTH');
    });

    it('has INVALID_SIGNATURE_LENGTH', () => {
      expect(ErrorCodes.INVALID_SIGNATURE_LENGTH).toBe('INVALID_SIGNATURE_LENGTH');
    });

    it('has INVALID_SEED_LENGTH', () => {
      expect(ErrorCodes.INVALID_SEED_LENGTH).toBe('INVALID_SEED_LENGTH');
    });

    it('has INVALID_CONTEXT_LENGTH', () => {
      expect(ErrorCodes.INVALID_CONTEXT_LENGTH).toBe('INVALID_CONTEXT_LENGTH');
    });
  });

  describe('type safety', () => {
    it('all error codes are strings', () => {
      expect(typeof ErrorCodes.WASM_NOT_INITIALIZED).toBe('string');
      expect(typeof ErrorCodes.INVALID_KEY_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_CIPHERTEXT_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_SIGNATURE_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_SEED_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_CONTEXT_LENGTH).toBe('string');
    });

    it('error codes are unique', () => {
      const codes = Object.values(ErrorCodes);
      const uniqueCodes = new Set(codes);
      expect(codes.length).toBe(uniqueCodes.size);
    });

    it('has exactly 6 error codes', () => {
      const codes = Object.keys(ErrorCodes);
      expect(codes.length).toBe(6);
    });
  });

  describe('usage in switch statements', () => {
    it('can be used in switch statement', () => {
      const handleError = (code: string): string => {
        switch (code) {
          case ErrorCodes.WASM_NOT_INITIALIZED:
            return 'Initialize WASM first';
          case ErrorCodes.INVALID_KEY_LENGTH:
            return 'Check key size';
          case ErrorCodes.INVALID_CIPHERTEXT_LENGTH:
            return 'Check ciphertext size';
          default:
            return 'Unknown error';
        }
      };

      expect(handleError(ErrorCodes.WASM_NOT_INITIALIZED)).toBe('Initialize WASM first');
      expect(handleError(ErrorCodes.INVALID_KEY_LENGTH)).toBe('Check key size');
      expect(handleError('UNKNOWN')).toBe('Unknown error');
    });
  });
});
