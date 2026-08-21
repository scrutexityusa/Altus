import type { Config } from '../config.js';
import { ProviderRegistry } from './provider.js';
import { SimulatedTreasuryProvider } from './simulated.js';

/**
 * Builds the provider registry for this deployment.
 *
 * There is one provider today and it is simulated. That is stated in the
 * configuration rather than assumed, so that a deployment which has *not* been
 * given a real provider cannot quietly execute against the simulated one and
 * have the receipts read as though money moved.
 *
 * `EXECUTION_PROVIDERS=none` registers nothing, and every enforced execution
 * is refused with ENFORCEMENT_UNAVAILABLE. That is the correct default posture
 * for a deployment whose integration is not finished: refusing is safe,
 * pretending is not.
 */
export function loadProviders(config: Config): ProviderRegistry {
  const names = config.EXECUTION_PROVIDERS.split(',')
    .map((name) => name.trim())
    .filter((name) => name.length > 0 && name !== 'none');

  return new ProviderRegistry(
    names.map((name) => {
      switch (name) {
        case 'simulated-treasury':
          if (config.isProduction) {
            // A simulated provider in production would produce receipts that
            // look exactly like real ones for money that never moved. There is
            // no configuration flag worth allowing that behind.
            throw new Error(
              'the simulated-treasury provider must not be enabled in production; ' +
                'set EXECUTION_PROVIDERS to a real provider or to "none"',
            );
          }
          return new SimulatedTreasuryProvider();
        default:
          throw new Error(`unknown execution provider "${name}"`);
      }
    }),
  );
}
