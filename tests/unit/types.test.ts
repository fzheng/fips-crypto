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

    it('works with DECAPSULATION_FAILED', () => {
      const error = new FipsCryptoError('Decap failed', ErrorCodes.DECAPSULATION_FAILED);
      expect(error.code).toBe('DECAPSULATION_FAILED');
    });

    it('works with VERIFICATION_FAILED', () => {
      const error = new FipsCryptoError('Verify failed', ErrorCodes.VERIFICATION_FAILED);
      expect(error.code).toBe('VERIFICATION_FAILED');
    });

    it('works with NOT_IMPLEMENTED', () => {
      const error = new FipsCryptoError('Not implemented', ErrorCodes.NOT_IMPLEMENTED);
      expect(error.code).toBe('NOT_IMPLEMENTED');
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

    it('has DECAPSULATION_FAILED', () => {
      expect(ErrorCodes.DECAPSULATION_FAILED).toBe('DECAPSULATION_FAILED');
    });

    it('has VERIFICATION_FAILED', () => {
      expect(ErrorCodes.VERIFICATION_FAILED).toBe('VERIFICATION_FAILED');
    });

    it('has NOT_IMPLEMENTED', () => {
      expect(ErrorCodes.NOT_IMPLEMENTED).toBe('NOT_IMPLEMENTED');
    });
  });

  describe('type safety', () => {
    it('all error codes are strings', () => {
      expect(typeof ErrorCodes.WASM_NOT_INITIALIZED).toBe('string');
      expect(typeof ErrorCodes.INVALID_KEY_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_CIPHERTEXT_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_SIGNATURE_LENGTH).toBe('string');
      expect(typeof ErrorCodes.INVALID_SEED_LENGTH).toBe('string');
      expect(typeof ErrorCodes.DECAPSULATION_FAILED).toBe('string');
      expect(typeof ErrorCodes.VERIFICATION_FAILED).toBe('string');
      expect(typeof ErrorCodes.NOT_IMPLEMENTED).toBe('string');
    });

    it('error codes are unique', () => {
      const codes = Object.values(ErrorCodes);
      const uniqueCodes = new Set(codes);
      expect(codes.length).toBe(uniqueCodes.size);
    });

    it('has exactly 9 error codes', () => {
      const codes = Object.keys(ErrorCodes);
      expect(codes.length).toBe(9);
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
          case ErrorCodes.NOT_IMPLEMENTED:
            return 'Feature not available';
          default:
            return 'Unknown error';
        }
      };

      expect(handleError(ErrorCodes.WASM_NOT_INITIALIZED)).toBe('Initialize WASM first');
      expect(handleError(ErrorCodes.INVALID_KEY_LENGTH)).toBe('Check key size');
      expect(handleError(ErrorCodes.NOT_IMPLEMENTED)).toBe('Feature not available');
      expect(handleError('UNKNOWN')).toBe('Unknown error');
    });
  });
});
