import { Config } from '../src/config.ts'
import { resolveIpPoolSettings } from '../src/ip-pool-settings/namespace.ts'
import test from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { configPaths, ensureToken, resolveConfig, writeAgentConfig, defaults } from '../src/config.ts'

test('resolveConfig fills defaults and keeps overrides', () => {
  const base = resolveConfig()
  assert.equal(base.providerId, defaults.providerId)
  assert.equal(base.apiKeyEnv, defaults.apiKeyEnv)
  assert.equal(base.restartMaxDelayMs, 60000)
  const custom = resolveConfig({ providerId: 'x', refreshSeconds: 60 })
  assert.equal(custom.providerId, 'x')
  assert.equal(custom.refreshSeconds, 60)
  assert.equal(custom.apiKeyEnv, defaults.apiKeyEnv)
})

test('ensureToken persists and reuses one token', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'o2ds-cfg-'))
  try {
    const paths = configPaths(dir)
    const first = await ensureToken(paths)
    assert.ok(first.length >= 40, 'token should be 32 bytes base64url')
    const second = await ensureToken(paths)
    assert.equal(first, second)
    const raw = await readFile(paths.tokenPath, 'utf8')
    assert.equal(raw.trim(), first)
    // blank stored value is regenerated
    await writeFile(paths.tokenPath, '\n')
    const third = await ensureToken(paths)
    assert.ok(third.length >= 40)
    assert.notEqual(third, '\n')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('writeAgentConfig emits the design.md section 8.3 template', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'o2ds-cfg-'))
  try {
    const paths = configPaths(dir)
    await writeAgentConfig(paths, { token: 'tok-1', refreshSeconds: 300 })
    const parsed = JSON.parse(await readFile(paths.configPath, 'utf8'))
    assert.equal(parsed.listen, '127.0.0.1:0')
    assert.deepEqual(parsed.server_keys, ['tok-1'])
    assert.equal(parsed.anonymous, true)
    assert.deepEqual(parsed.zen_keys, [])
    assert.deepEqual(parsed.go_keys, [])
    assert.equal(parsed.upstream.zen, 'https://opencode.ai/inference')
    assert.equal(parsed.models.refresh_seconds, 300)
    assert.deepEqual(parsed.proxies, ['direct'])
    // rewrite with new values replaces atomically
    await writeAgentConfig(paths, { token: 'tok-2', refreshSeconds: 60 })
    const next = JSON.parse(await readFile(paths.configPath, 'utf8'))
    assert.deepEqual(next.server_keys, ['tok-2'])
    assert.equal(next.models.refresh_seconds, 60)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('Config preserves subscription URLs from an older profile patch', () => {
  const config = Config({ ipPool: { subscriptions: ['https://example.test/sub'] } })
  const value = resolveIpPoolSettings(JSON.parse(JSON.stringify(config.ipPool.get())))
  assert.deepEqual(value.subscription.urls, ['https://example.test/sub'])
})

test('Config declares and bounds the stream watchdog windows, undefined when unset', () => {
  // issue #33: nothing reached ZenAdapter's constructor, so the windows were
  // unreachable. Declaring them here is what makes them settable — and, unlike
  // an undeclared key (schemastery passes those through unvalidated), it also
  // makes the schema reject a nonsensical window instead of arming it.
  const config = Config({ firstEventMs: 300, bodyIdleMs: 900, responsesBodyIdleMs: 1800 })
  assert.equal(config.firstEventMs, 300)
  assert.equal(config.bodyIdleMs, 900)
  assert.equal(config.responsesBodyIdleMs, 1800)
  for (const key of ['firstEventMs', 'bodyIdleMs', 'responsesBodyIdleMs'] as const) {
    for (const value of [-1, 0, 0.5, 600_001, 2 ** 31, Infinity, NaN, '300']) {
      assert.throws(() => Config({ [key]: value }), new RegExp(key))
    }
    assert.equal(Config({ [key]: 1 })[key], 1)
    assert.equal(Config({ [key]: 600_000 })[key], 600_000)
  }
  // No schema default on purpose: an unset window must stay undefined so the
  // adapter's own `?? DEFAULT_*_MS` owns the shipped number (one source).
  const bare = Config({})
  assert.equal(bare.firstEventMs, undefined)
  assert.equal(bare.bodyIdleMs, undefined)
  assert.equal(bare.responsesBodyIdleMs, undefined)
  // resolveConfig() is `{ ...defaults, ...config }`: the keys ride through the
  // plain ordinary half apply() hands it, untouched by `defaults`.
  assert.equal(resolveConfig({ firstEventMs: 300 }).firstEventMs, 300)
  assert.equal(resolveConfig().firstEventMs, undefined)
})

test('Config declares the allowedModels whitelist, empty by default (issue #83)', () => {
  // Absent = empty = expose-all: the whitelist is a narrowing pass over the
  // existing catalog rules, never an override (see the catalog tests).
  assert.deepEqual(Config({}).allowedModels, [])
  // The issue's yaml example shape round-trips as a plain string array.
  const issue = ['deepseek-v4.1-flash-free', 'mimo-v2.6-flash-free', 'glm-5.3-flash-free', 'nemotron-3.5-super-vl-free']
  const config = Config({ allowedModels: issue })
  assert.deepEqual(JSON.parse(JSON.stringify(config.allowedModels)), issue)
  // A non-array is rejected rather than armed.
  assert.throws(() => Config({ allowedModels: 'big-pickle' } as never))
  // resolveConfig passes the list through untouched; a raw (schema-less)
  // config simply has no key at all.
  assert.deepEqual(resolveConfig({ allowedModels: issue }).allowedModels, issue)
  assert.equal(resolveConfig().allowedModels, undefined)
})

test('Config declares the delegation block, disabled by default, with per-field bounds', () => {
  // issue #76: the delegation block must be reachable and validated like every
  // other config field. Schemastery instantiates the nested object even when
  // absent, so the shipped default is `enabled: false` — the block is inert and
  // the anonymous path is unchanged unless the user explicitly enables it.
  const bare = Config({})
  assert.equal(bare.delegation.enabled, false, 'absent delegation defaults to disabled')

  const config = Config({ delegation: { enabled: true } })
  assert.equal(config.delegation.enabled, true)
  assert.equal(config.delegation.minVersion, '1.18.0')
  assert.equal(config.delegation.memLimit, '96MiB')
  assert.equal(config.delegation.gcPercent, 30)
  assert.equal(config.delegation.trimIntervalMs, 60_000)
  assert.equal(config.delegation.startTimeoutMs, 60_000)
  assert.equal(config.delegation.opencodePath, '')
  assert.equal(config.delegation.tools, false, 'tools-relay is opt-in: absent keeps the text-only ceiling')
  assert.equal(config.delegation.cwd, '', 'empty cwd means the host process cwd')

  const custom = Config({ delegation: { enabled: true, opencodePath: '/usr/bin/opencode', gcPercent: 50, trimIntervalMs: 0 } })
  assert.equal(custom.delegation.opencodePath, '/usr/bin/opencode')
  assert.equal(custom.delegation.gcPercent, 50)
  assert.equal(custom.delegation.trimIntervalMs, 0)

  // Out-of-range knobs are rejected rather than armed.
  assert.throws(() => Config({ delegation: { gcPercent: 0 } }), /gcPercent/)
  assert.throws(() => Config({ delegation: { trimIntervalMs: -1 } }), /trimIntervalMs/)
  assert.throws(() => Config({ delegation: { startTimeoutMs: 10 } }), /startTimeoutMs/)

  // resolveConfig passes an explicitly-set block through untouched; a raw
  // (schema-less) config simply has no delegation key at all.
  assert.equal(resolveConfig({ delegation: { enabled: true } }).delegation?.enabled, true)
  assert.equal(resolveConfig().delegation, undefined)
})
