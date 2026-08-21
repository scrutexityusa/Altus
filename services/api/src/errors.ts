import { ZodError } from 'zod';
import { ScrutexityError } from '@scrutexity/core';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Logger } from './logger.js';

/**
 * The single place an error becomes a response.
 *
 * Two rules hold everywhere: a failure never becomes a success, and the body a
 * client sees never carries policy internals or another tenant's object graph.
 * The full detail goes to the log, keyed by the same request id the client was
 * given, so support can join the two without the client learning anything.
 */
export function toErrorResponse(
  error: unknown,
  request: FastifyRequest,
  reply: FastifyReply,
  logger: Logger,
): void {
  const requestId = request.id;

  if (error instanceof ZodError) {
    const details = error.issues.map((issue) => ({
      path: issue.path.join('.'),
      message: issue.message,
    }));
    logger.info({ requestId, code: 'INVALID_REQUEST', details }, 'request rejected by schema');
    reply.code(400).send({
      error: { code: 'INVALID_REQUEST', message: 'The request is invalid.', details, request_id: requestId },
    });
    return;
  }

  if (error instanceof ScrutexityError) {
    logger[error.status >= 500 ? 'error' : 'info'](
      {
        requestId,
        code: error.code,
        message: error.message,
        details: error.details,
        internal: error.internal,
      },
      'request failed',
    );
    reply.code(error.status).send(error.toBody(requestId));
    return;
  }

  // Framework-level rejections -- body too large, unsupported media type,
  // malformed JSON -- already carry the right status. Collapsing them into a
  // 500 would tell a caller the service broke when in fact it refused them.
  const framework = error as { statusCode?: number; code?: string } | null;
  if (
    typeof framework?.statusCode === 'number' &&
    framework.statusCode >= 400 &&
    framework.statusCode < 500 &&
    typeof framework.code === 'string' &&
    framework.code.startsWith('FST_')
  ) {
    logger.info({ requestId, code: framework.code, status: framework.statusCode }, 'request rejected');
    reply.code(framework.statusCode).send({
      error: {
        code: framework.statusCode === 429 ? 'RATE_LIMITED' : 'INVALID_REQUEST',
        reason_code: framework.code,
        message: 'The request is invalid.',
        request_id: requestId,
      },
    });
    return;
  }

  // Postgres raises this when an append-only trigger or an RLS policy blocks a
  // write. Either is a bug or an attack; neither is described to the caller.
  const pgCode = (error as { code?: string } | null)?.code;
  if (pgCode === '42501') {
    logger.error({ requestId, pgCode, err: error }, 'write blocked by database policy');
    reply.code(403).send({
      error: {
        code: 'FORBIDDEN',
        message: 'The caller is not permitted to perform this operation.',
        request_id: requestId,
      },
    });
    return;
  }

  logger.error({ requestId, err: error }, 'unhandled error');
  reply.code(500).send({
    error: { code: 'INTERNAL_ERROR', message: 'An internal error occurred.', request_id: requestId },
  });
}
