import { pino } from 'pino';
import type { FastifyBaseLogger } from 'fastify';
import type { Config } from './config.js';

/**
 * Structured JSON logging. Every line carries the request id, so a decision
 * can be traced from the HTTP edge through evaluation to the receipt it
 * produced.
 *
 * The redaction list is not decoration: authorization request context routinely
 * carries counterparty account details, and bearer tokens must never reach a
 * log aggregator.
 */
export function createLogger(config: Config): FastifyBaseLogger {
  return pino({
    level: config.LOG_LEVEL,
    base: { service: 'scrutexity-api', env: config.NODE_ENV },
    redact: {
      paths: [
        'req.headers.authorization',
        'req.headers["idempotency-key"]',
        'body.token',
        'token',
        '*.token_hash',
      ],
      remove: true,
    },
    formatters: { level: (label) => ({ level: label }) },
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}

/**
 * Typed as FastifyBaseLogger so one logger instance serves both the HTTP layer
 * and the services beneath it. Two loggers would eventually diverge in level,
 * redaction or destination -- and the redaction list here is a security control.
 */
export type Logger = FastifyBaseLogger;
