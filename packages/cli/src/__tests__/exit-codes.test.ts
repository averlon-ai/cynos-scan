import { describe, expect, test } from 'bun:test';
import { CommanderError } from 'commander';
import { mockEngine } from './engine-mock';

mockEngine();
const { CliError, errorKind, EXIT, exitCodeFor, refusalKind, scanExitCode, stopError } =
  await import('../exit-codes');
const { EngineUnavailable } = await import('../engine');

const outcome = (scanStatus: string, exitCode: number | null) => ({
  exitCode,
  outcome: { scanStatus },
});

describe('scanExitCode: upstream exit codes pass through', () => {
  test('a completed scan exits 0, or 1 when the severity policy failed', () => {
    expect(scanExitCode(outcome('completed', 0))).toBe(EXIT.ok);
    expect(scanExitCode(outcome('completed', 1))).toBe(EXIT.policy);
  });

  test('a validated dry run exits 0', () => {
    expect(scanExitCode(outcome('skipped', 0))).toBe(EXIT.ok);
    expect(scanExitCode(outcome('skipped', 2))).toBe(EXIT.failure);
  });

  test('a failed scan exits 2, even when upstream exited 0', () => {
    expect(scanExitCode(outcome('failed', 0))).toBe(EXIT.failure);
    expect(scanExitCode(outcome('failed', null))).toBe(EXIT.failure);
  });

  test("upstream's own 130 and 143 pass through", () => {
    expect(scanExitCode(outcome('failed', 130))).toBe(EXIT.interrupted);
    expect(scanExitCode(outcome('failed', 143))).toBe(EXIT.terminated);
  });

  test('a scan the user stopped is 130 or 143, unless it completed anyway', () => {
    expect(scanExitCode(outcome('failed', null), 'SIGINT')).toBe(130);
    expect(scanExitCode(outcome('failed', 2), 'SIGTERM')).toBe(143);
    expect(scanExitCode(outcome('completed', 1), 'SIGINT')).toBe(1);
  });

  test('a scan --timeout stopped is a failure, 2, whatever upstream exited with', () => {
    expect(scanExitCode(outcome('failed', 130), 'timeout')).toBe(EXIT.failure);
    expect(scanExitCode(outcome('failed', null), 'timeout')).toBe(EXIT.failure);
    expect(scanExitCode(outcome('completed', 0), 'timeout')).toBe(EXIT.ok);
  });
});

describe('our failures map onto 2, with a kind', () => {
  const cases: [unknown, string, number][] = [
    [new CliError('usage', 'bad flag'), 'usage', 2],
    [new CliError('auth', 'no key'), 'auth', 2],
    [new Error('cynos refused the key for m (HTTP 401: {}). Check the key.'), 'auth', 2],
    [
      new Error("cynos refused the request for m: the key's budget is spent (HTTP 402)"),
      'budget',
      2,
    ],
    [new Error('cynos cannot serve the model m for this key (HTTP 400: {})'), 'model', 2],
    [new Error('cynos is unreachable at https://gw/v1 (unreachable: ENOTFOUND)'), 'network', 2],
    [new Error('cynos could not answer the key check for m (HTTP 503: x)'), 'gateway', 2],
    [
      new Error('The knowledge base could not be built, so no scan was started: x'),
      'knowledge-base',
      2,
    ],
    [new Error("Codex's sandbox could not start (upstream's container check): y"), 'host-check', 2],
    [new Error('The scan stopped before scanning began: z'), 'host-check', 2],
    [new Error('The scan was stopped: interrupted'), 'interrupted', 130],
    [new Error('The scan was stopped: timed out after 2h'), 'timed-out', 2],
    [new EngineUnavailable('checkHost'), 'engine', 2],
    [new Error('something else'), 'internal', 2],
  ];
  for (const [error, kind, code] of cases)
    test(`${(error as Error).constructor.name}: ${(error as Error).message.slice(0, 40)} is ${kind}, exit ${code}`, () => {
      expect(errorKind(error)).toBe(kind as never);
      expect(exitCodeFor(error)).toBe(code);
    });

  test("commander's usage errors are 2, help and version 0", () => {
    expect(exitCodeFor(new CommanderError(1, 'commander.unknownCommand', 'unknown command'))).toBe(
      2
    );
    expect(exitCodeFor(new CommanderError(0, 'commander.helpDisplayed', '(outputHelp)'))).toBe(0);
    expect(errorKind(new CommanderError(1, 'commander.unknownOption', 'x'))).toBe('usage');
  });
});

describe('a stopped run fails as its stop, whichever step it cut short', () => {
  const kbFailed = new Error(
    'The knowledge base could not be built, so no scan was started: graph exited'
  );

  test('the stop gives the kind and the exit code, and the step keeps its message', () => {
    const cases: [Parameters<typeof stopError>[1], string, string, number][] = [
      ['timeout', 'timed out after 1s', 'timed-out', 2],
      ['SIGINT', 'interrupted (Ctrl-C)', 'interrupted', 130],
      ['SIGTERM', 'terminated (SIGTERM)', 'terminated', 143],
    ];
    for (const [cause, reason, kind, code] of cases) {
      const error = stopError(kbFailed, cause, reason);
      expect(errorKind(error)).toBe(kind as never);
      expect(exitCodeFor(error)).toBe(code);
      expect((error as Error).message).toBe(`The scan was stopped: ${reason}. ${kbFailed.message}`);
      expect((error as { stopped?: string }).stopped).toBe(reason);
    }
  });

  test("the engine's own stop message is kept as it is", () => {
    const error = stopError(
      new Error('The scan was stopped: terminated (SIGTERM)'),
      'SIGTERM',
      'x'
    );
    expect((error as Error).message).toBe('The scan was stopped: terminated (SIGTERM)');
    expect(exitCodeFor(error)).toBe(EXIT.terminated);
  });

  test('an error of a run nothing stopped passes through', () => {
    expect(stopError(kbFailed, undefined, undefined)).toBe(kbFailed);
  });
});

describe("a refused key check's kind, for login", () => {
  test('follows the refusal, and an unclassified one is the key', () => {
    expect(refusalKind('key')).toBe('auth');
    expect(refusalKind('budget')).toBe('budget');
    expect(refusalKind('model')).toBe('model');
    expect(refusalKind('unreachable')).toBe('network');
    expect(refusalKind('gateway')).toBe('gateway');
    expect(refusalKind(undefined)).toBe('auth');
  });
});
