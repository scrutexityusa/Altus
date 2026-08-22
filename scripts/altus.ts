/**
 * The `altus` command.
 *
 * A thin dispatcher, and thin on purpose: each subcommand is its own script
 * with its own concerns and its own connection requirements. `migrate` is a
 * schema lifecycle operation; `bootstrap` creates principals and issues a
 * credential. Folding them into one command would make the migration runner --
 * which every operator runs on every deploy -- capable of minting an
 * administrative credential.
 *
 * This exists so the documented flow is three commands a stranger can type
 * rather than three `tsx scripts/...` invocations they have to be told about.
 */
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

const COMMANDS: Record<string, { script: string; summary: string }> = {
  migrate: { script: 'scripts/migrate.ts', summary: 'Apply pending schema migrations' },
  bootstrap: {
    script: 'scripts/bootstrap.ts',
    summary: 'Create the first organization and its administrator (runs once)',
  },
  demo: { script: 'scripts/demo.ts', summary: 'Run the treasury demo from a clean database' },
};

const USAGE = `
altus -- machine authority control plane

USAGE
  pnpm altus <command> [options]

COMMANDS
${Object.entries(COMMANDS)
  .map(([name, { summary }]) => `  ${name.padEnd(12)}${summary}`)
  .join('\n')}

  Run \`pnpm altus <command> --help\` for a command's own options.

GETTING STARTED
  docker compose up -d
  pnpm altus migrate
  ALTUS_BOOTSTRAP_DATABASE_URL=postgres://owner:pass@host:5432/db \\
    pnpm altus bootstrap --org-name "Example Treasury" \\
                         --admin-name "Jane Smith" \\
                         --admin-email "jane@example.com"
`;

const [command, ...rest] = process.argv.slice(2);

if (!command || command === '--help' || command === '-h') {
  process.stdout.write(USAGE);
  process.exit(0);
}

const entry = COMMANDS[command];
if (!entry) {
  process.stderr.write(`\n  unknown command "${command}"\n${USAGE}`);
  process.exit(1);
}

// Inherit stdio so a subcommand's prompts, colours and exit code are the
// operator's, not this wrapper's.
const child = spawn('pnpm', ['exec', 'tsx', entry.script, ...rest], {
  cwd: root,
  stdio: 'inherit',
});
child.on('exit', (code, signal) => {
  process.exit(signal ? 1 : (code ?? 0));
});
