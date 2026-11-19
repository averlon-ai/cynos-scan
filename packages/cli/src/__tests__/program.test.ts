import { describe, expect, test } from 'bun:test';
import { mockEngine, captureOutput } from './engine-mock';

mockEngine();
const { createContext } = await import('../context');
const { buildProgram, commandManifest } = await import('../program');
const { allCommands, examplesOf } = await import('../help');
const { run } = await import('../cli');
const { completionScript } = await import('../commands/completion');
const { TOPICS } = await import('../commands/help-topics');
const { collectChecks } = await import('../commands/doctor');

const env = (): NodeJS.ProcessEnv => ({
  CI: '1',
  CYNOS_CREDENTIAL_STORE: 'file',
  XDG_CONFIG_HOME: '/nonexistent',
  NO_COLOR: '1',
});
const program = () => buildProgram(createContext(env()));

const EXPECTED = [
  'scan',
  'scans list',
  'scans findings',
  'scans export',
  'scans logs',
  'login',
  'logout',
  'auth status',
  'doctor',
  'update',
  'info',
  'debug bundle',
  'gc',
  'completion',
  'help',
];

describe('the command tree', () => {
  test('has every command of the plan', () => {
    const names = allCommands(program()).map(entry => entry.name);
    for (const name of EXPECTED) expect(names).toContain(name);
  });

  test('every command has examples, and every example uses the command', () => {
    for (const { name, command } of allCommands(program())) {
      const examples = examplesOf(command);
      expect({ name, examples: examples.length > 0 }).toEqual({ name, examples: true });
      for (const example of examples)
        expect({ name, example }).toEqual({
          name,
          example: expect.stringMatching(/^(printf .*\| )?cynos /),
        });
    }
  });

  test('every command help shows its examples', () => {
    for (const { command } of allCommands(program())) {
      let help = '';
      command.configureOutput({ writeOut: text => void (help += text) });
      command.outputHelp();
      expect(help).toContain('Examples:');
    }
  });

  test('the root help is grouped by task', async () => {
    const { stdout } = await captureOutput(() => run([], env()));
    for (const group of [
      'Get started:',
      'Scan:',
      'Review results:',
      'Sign in:',
      'Setup and support:',
      'Shell and help:',
    ])
      expect(stdout).toContain(group);
    expect(stdout).toContain(
      'Topics: auth, runtimes, diff-scans, knowledge-base, scan-inputs, exit-codes, env'
    );
  });
});

describe('--llms', () => {
  test('prints one JSON manifest with every command, its options and examples', async () => {
    const { stdout, value } = await captureOutput(() => run(['--llms'], env()));
    expect(value).toBe(0);
    const manifest = JSON.parse(stdout) as {
      commands: { name: string; examples: string[]; options: unknown[] }[];
      exitCodes: object;
    };
    expect(manifest.commands.map(command => command.name)).toEqual(
      expect.arrayContaining(EXPECTED)
    );
    for (const command of manifest.commands) expect(command.examples.length).toBeGreaterThan(0);
    expect(Object.keys(manifest.exitCodes)).toEqual(['0', '1', '2', '130', '143']);
    const scan = manifest.commands.find(command => command.name === 'scan')!;
    for (const option of ['--since-last-scan', '--scan-prompt-file', '--timeout', '--host-path'])
      expect(JSON.stringify(scan.options)).toContain(option);
  });

  test('matches commandManifest', () => {
    const built = commandManifest(program());
    expect(built['name']).toBe('cynos');
  });
});

describe('usage errors', () => {
  test('a typo exits 2 with a did-you-mean suggestion', async () => {
    const { value, stderr } = await captureOutput(() => run(['sacn'], env()));
    expect(value).toBe(2);
    expect(stderr).toContain('Did you mean scan?');
  });

  test('an unknown option exits 2', async () => {
    const { value, stderr } = await captureOutput(() => run(['doctor', '--frobnicate'], env()));
    expect(value).toBe(2);
    expect(stderr).toContain('unknown option');
  });

  test('--version exits 0', async () => {
    const { value, stdout } = await captureOutput(() => run(['--version'], env()));
    expect(value).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe('help topics and completion', () => {
  test('every topic has text', async () => {
    for (const topic of Object.keys(TOPICS)) {
      const { stdout, value } = await captureOutput(() => run(['help', topic], env()));
      expect(value).toBe(0);
      expect(stdout.length).toBeGreaterThan(50);
    }
  });

  test('completion scripts name the commands and their options', () => {
    for (const shell of ['bash', 'zsh', 'fish']) {
      const script = completionScript(program(), shell);
      expect(script).toContain('cynos');
      expect(script).toContain('since-last-scan');
      expect(script).toContain('doctor');
    }
    expect(() => completionScript(program(), 'tcsh')).toThrow(/completion takes/);
  });
});

test('doctor does not require registry credentials for the public npm package', async () => {
  const context = createContext({ ...env(), XDG_CACHE_HOME: '/nonexistent' });
  const checks = await collectChecks(context, [], { quick: true });
  expect(checks.map(check => check.id)).toEqual(['login', 'update']);
  expect(JSON.stringify(checks)).not.toContain('GITHUB_TOKEN');
});
