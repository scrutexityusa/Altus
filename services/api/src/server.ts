import { buildApp } from './app.js';

/**
 * Process entrypoint. Boots the app, then installs signal handlers that drain
 * in-flight requests before exiting: a control plane that drops a request
 * mid-decision leaves an authorization request with no decision attached to it.
 */
const app = await buildApp();

try {
  await app.server.listen({ port: app.config.PORT, host: app.config.HOST });
  app.logger.info({ port: app.config.PORT }, 'scrutexity api listening');
} catch (error) {
  app.logger.fatal({ err: error }, 'failed to start');
  process.exit(1);
}

let shuttingDown = false;
for (const signal of ['SIGTERM', 'SIGINT'] as const) {
  process.on(signal, () => {
    if (shuttingDown) return;
    shuttingDown = true;
    app.logger.info({ signal }, 'draining');
    app
      .close()
      .then(() => process.exit(0))
      .catch((error) => {
        app.logger.error({ err: error }, 'shutdown failed');
        process.exit(1);
      });
  });
}
