import { randomUUID } from 'node:crypto';
import Fastify, { type FastifyInstance } from 'fastify';
import { trace, type Span } from '@opentelemetry/api';
import { loadConfig, type Config } from './config.js';
import { createLogger, type Logger } from './logger.js';
import { createDatabase, type Database } from './db/pool.js';
import { authenticate } from './auth.js';
import { toErrorResponse } from './errors.js';
import { metrics, renderMetrics } from './metrics.js';
import { loadEvidenceKeys, type EvidenceKeys } from './services/evidence.js';
import { registerRoutes } from './routes/index.js';

export interface App {
  server: FastifyInstance;
  db: Database;
  config: Config;
  keys: EvidenceKeys;
  logger: Logger;
  close(): Promise<void>;
}

const tracer = trace.getTracer('scrutexity-api');

/**
 * Endpoints that do not require a credential. Everything else does; there is
 * no route-level opt-out, because a missed `preHandler` on one route is how
 * authorization services get bypassed.
 */
const PUBLIC_PATHS = new Set(['/health', '/ready', '/metrics']);

export async function buildApp(overrides: Partial<Config> = {}): Promise<App> {
  const config = { ...loadConfig(), ...overrides } as Config;
  const logger = createLogger(config);
  const db = createDatabase(config);
  const keys = loadEvidenceKeys(config);

  const server = Fastify({
    loggerInstance: logger,
    // The client may supply a correlation id, but it never becomes the trusted
    // identity of anything -- it only joins log lines together.
    genReqId: (req) => (req.headers['x-request-id'] as string | undefined)?.slice(0, 128) ?? randomUUID(),
    // Fastify's own per-request lines are replaced by the structured
    // onResponse record below, which carries the tenant and principal.
    // Deprecated in favour of `logController` in Fastify 5, which currently
    // requires constructing a full LogController; revisit before Fastify 6
    // removes this option.
    disableRequestLogging: true,
    bodyLimit: 256 * 1024,
    trustProxy: true,
  });

  server.addHook('onRequest', async (request, reply) => {
    reply.header('x-request-id', request.id);
    (request as unknown as { startedAt: number }).startedAt = performance.now();
  });

  server.addHook('preHandler', async (request) => {
    if (PUBLIC_PATHS.has(request.url.split('?')[0]!)) return;
    request.principal = await authenticate(db, request.headers.authorization);
  });

  server.addHook('onResponse', async (request, reply) => {
    const route = request.routeOptions.url ?? 'unmatched';
    const started = (request as unknown as { startedAt?: number }).startedAt;
    metrics.httpRequests.inc({ route, method: request.method, status: String(reply.statusCode) });
    if (started !== undefined) {
      metrics.httpLatency.observe((performance.now() - started) / 1000, { route, method: request.method });
    }
    logger.info(
      {
        requestId: request.id,
        method: request.method,
        route,
        status: reply.statusCode,
        durationMs: started === undefined ? null : Math.round(performance.now() - started),
        organizationId: request.principal?.organization_id ?? null,
        principal: request.principal ? `${request.principal.type}:${request.principal.id}` : null,
      },
      'request completed',
    );
  });

  server.setErrorHandler((error, request, reply) => {
    toErrorResponse(error, request, reply, logger);
  });

  server.setNotFoundHandler((request, reply) => {
    reply.code(404).send({
      error: { code: 'NOT_FOUND', message: 'Not found.', request_id: request.id },
    });
  });

  // Liveness: the process is up. Deliberately does not touch the database --
  // a liveness probe that fails on a database blip restarts a healthy service.
  server.get('/health', async () => ({ status: 'ok', service: 'scrutexity-api' }));

  // Readiness: this instance can actually make decisions.
  server.get('/ready', async (_request, reply) => {
    try {
      await db.withoutTenant(async (client) => client.query('SELECT 1'));
      return { status: 'ready' };
    } catch (error) {
      logger.error({ err: error }, 'readiness check failed');
      reply.code(503);
      return { status: 'not_ready', reason: 'database_unavailable' };
    }
  });

  server.get('/metrics', async (_request, reply) => {
    reply.header('content-type', 'text/plain; version=0.0.4');
    return renderMetrics();
  });

  await server.register(async (instance) => {
    instance.addHook('preHandler', async (request) => {
      const span: Span = tracer.startSpan(`${request.method} ${request.routeOptions.url ?? request.url}`);
      span.setAttribute('scrutexity.request_id', String(request.id));
      if (request.principal) {
        span.setAttribute('scrutexity.organization_id', request.principal.organization_id);
        span.setAttribute('scrutexity.principal_type', request.principal.type);
      }
      (request as unknown as { span: Span }).span = span;
    });
    instance.addHook('onResponse', async (request) => {
      (request as unknown as { span?: Span }).span?.end();
    });
    await registerRoutes(instance, { db, keys });
  });

  return {
    server,
    db,
    config,
    keys,
    logger,
    close: async () => {
      await server.close();
      await db.close();
    },
  };
}
