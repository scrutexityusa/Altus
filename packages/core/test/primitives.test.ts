import { describe, expect, it } from 'vitest';
import { canonicalize, hashObject, CanonicalizationError } from '../src/canonical.js';
import { compareDecimal, toDecimalString, DecimalError } from '../src/decimal.js';
import { compareMoney, formatMoney, MoneyError, parseMoney } from '../src/money.js';
import { idTimestamp, isId, newId } from '../src/ids.js';
import { isExpired, manualClock } from '../src/time.js';

describe('canonical JSON', () => {
  it('is independent of key insertion order', () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe(canonicalize({ a: 2, b: 1 }));
    expect(hashObject({ z: [1, 2], a: 'x' })).toBe(hashObject({ a: 'x', z: [1, 2] }));
  });

  it('treats an omitted property and an undefined property identically', () => {
    expect(hashObject({ a: 1, b: undefined })).toBe(hashObject({ a: 1 }));
  });

  it('refuses floats so a receipt can never depend on a shortest-round-trip', () => {
    expect(() => canonicalize({ amount: 0.1 + 0.2 })).toThrow(CanonicalizationError);
    expect(() => canonicalize({ score: 0.97 })).toThrow(CanonicalizationError);
    expect(canonicalize({ score: '0.97' })).toBe('{"score":"0.97"}');
  });

  it('rejects NaN, Infinity and unsafe integers', () => {
    for (const bad of [Number.NaN, Infinity, -Infinity, 2 ** 60]) {
      expect(() => canonicalize({ bad })).toThrow(CanonicalizationError);
    }
  });

  it('serialises bigint and Date deterministically', () => {
    expect(canonicalize({ n: 10n, at: new Date('2026-03-01T00:00:00Z') })).toBe(
      '{"at":"2026-03-01T00:00:00.000Z","n":"10"}',
    );
  });
});

describe('money', () => {
  it('parses decimal strings into exact minor units', () => {
    expect(parseMoney('750000.00', 'USD').amountMinor).toBe('75000000');
    expect(parseMoney('0.01', 'USD').amountMinor).toBe('1');
    expect(parseMoney('1000', 'JPY').amountMinor).toBe('1000');
    expect(parseMoney('1.234', 'KWD').amountMinor).toBe('1234');
  });

  it('round-trips through formatting', () => {
    for (const [amount, currency] of [
      ['750000.00', 'USD'],
      ['0.05', 'EUR'],
      ['1000', 'JPY'],
      ['1.234', 'BHD'],
    ] as const) {
      expect(formatMoney(parseMoney(amount, currency))).toBe(
        currency === 'JPY' ? '1000' : amount === '750000.00' ? '750000.00' : amount,
      );
    }
  });

  it('refuses precision the currency does not have', () => {
    expect(() => parseMoney('1.005', 'USD')).toThrow(MoneyError);
    expect(() => parseMoney('1.5', 'JPY')).toThrow(MoneyError);
  });

  it('refuses fractional JS numbers, which cannot be trusted to be exact', () => {
    expect(() => parseMoney(0.1 + 0.2, 'USD')).toThrow(MoneyError);
    expect(parseMoney(25000, 'USD').amountMinor).toBe('2500000');
  });

  it('refuses cross-currency comparison rather than inventing a rate', () => {
    expect(() => compareMoney(parseMoney('1', 'USD'), parseMoney('1', 'EUR'))).toThrow(MoneyError);
  });

  it('compares exactly at the boundary', () => {
    const fifty = parseMoney('50000', 'USD');
    expect(compareMoney(parseMoney('49999.99', 'USD'), fifty)).toBe(-1);
    expect(compareMoney(parseMoney('50000.00', 'USD'), fifty)).toBe(0);
    expect(compareMoney(parseMoney('50000.01', 'USD'), fifty)).toBe(1);
  });
});

describe('decimal', () => {
  it('compares without floating point', () => {
    expect(compareDecimal('0.9', '0.90')).toBe(0);
    expect(compareDecimal('0.1', '0.09999999')).toBe(1);
    expect(compareDecimal('10', '9.999')).toBe(1);
    expect(compareDecimal('-1', '0')).toBe(-1);
    expect(compareDecimal('-2', '-1')).toBe(-1);
  });

  it('normalises authored numbers but rejects exponential notation', () => {
    expect(toDecimalString(0.9)).toBe('0.9');
    expect(toDecimalString('0.900')).toBe('0.9');
    // Leading zeros are rejected rather than normalised: a policy threshold is
    // reviewed by humans, and "007" is a typo worth surfacing.
    expect(() => toDecimalString('007')).toThrow(DecimalError);
    expect(() => toDecimalString(1e21)).toThrow(DecimalError);
    expect(() => toDecimalString('abc')).toThrow(DecimalError);
  });
});

describe('identifiers', () => {
  it('are prefixed, recognisable and time-sortable', () => {
    const a = newId('lease', 1_700_000_000_000);
    const b = newId('lease', 1_700_000_001_000);
    expect(isId('lease', a)).toBe(true);
    expect(isId('agent', a)).toBe(false);
    expect(a < b).toBe(true);
    expect(idTimestamp(a)).toBe(1_700_000_000_000);
  });

  it('stays monotonic within a single millisecond', () => {
    const ids = Array.from({ length: 500 }, () => newId('receipt', 1_700_000_000_000));
    expect([...ids].sort()).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('time', () => {
  it('treats the expiry instant itself as expired', () => {
    const at = new Date('2026-03-01T12:00:00Z');
    expect(isExpired(at, at)).toBe(true);
    expect(isExpired(at, new Date(at.getTime() - 1))).toBe(false);
  });

  it('provides a clock tests can advance without sleeping', () => {
    const clock = manualClock('2026-03-01T00:00:00Z');
    const before = clock.now();
    clock.advance(1000);
    expect(clock.now().getTime() - before.getTime()).toBe(1000);
  });
});
