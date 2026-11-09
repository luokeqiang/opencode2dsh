import test from 'node:test'
import assert from 'node:assert/strict'
import { isFreeTierRefusal, ZenAdapter } from '../src/adapter/zen-adapter.ts'
import type { DelegationDelegate } from '../src/adapter/delegate.ts'
import type { HarnessChunk, PiDoneMessage, PiEvent } from '../src/adapter/events.ts'
import type { HarnessGenerateOptions } from '../src/adapter/messages.ts'

const options: HarnessGenerateOptions = {
  provider: 'opencode2dsh',
  model: 'big-pickle',
  messages: [{ role: 'user', content: [{ type: 'text', text: 'ping' }] }],
  maxTokens: 16,
}

function message(overrides: Partial<PiDoneMessage> = {}): PiDoneMessage {
  return {
    api: 'openai-completions',
    provider: 'opencode2dsh',
    model: options.model,
    content: [],
    stopReason: 'stop',
    usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2 },
    ...overrides,
  }
}

/** The anonymous lane's FreeTierError credential refusal, as pi-ai reports it. */
function freeTierRefused(): PiEvent[] {
  return [{
    type: 'error',
    error: message({
      stopReason: 'error',
      content: [],
      errorMessage: '403 FreeTierError: free tier can only be used from within OpenCode',
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0 },
    }),
  }]
}

/** A region refusal — a different class the delegate must NOT rescue. */
function regionRefused(): PiEvent[] {
  return [{
    type: 'error',
    error: message({
      stopReason: 'error',
      content: [],
      errorMessage: '403 RegionError: not available in your country',
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0 },
    }),
  }]
}

function answered(text = 'OK'): PiEvent[] {
  const partial = { content: [{ type: 'text', text }] }
  return [
    { type: 'text_start', contentIndex: 0, partial },
    { type: 'text_delta', contentIndex: 0, delta: text, partial },
    { type: 'text_end', contentIndex: 0, content: text, partial },
    { type: 'done', message: message({ stopReason: 'stop', content: partial.content }) },
  ]
}

const delegateChunks: HarnessChunk[] = [
  { type: 'block-start', index: 0, blockType: 'text' },
  { type: 'text-delta', index: 0, text: 'delegated answer' },
  { type: 'block-end', index: 0, block: { type: 'text', text: 'delegated answer' } },
  { type: 'usage', usage: { inputTokens: 2, outputTokens: 3 } },
  { type: 'finish', reason: { kind: 'stop' } },
]

function fakeDelegate(
  behavior: { ready?: boolean; chunks?: HarnessChunk[]; error?: Error },
  calls: { ready: number; stream: number },
): DelegationDelegate {
  return {
    ready: async () => {
      calls.ready += 1
      return behavior.ready ?? true
    },
    stream: async function* (): AsyncGenerator<HarnessChunk> {
      calls.stream += 1
      if (behavior.error) throw behavior.error
      for (const chunk of behavior.chunks ?? []) yield chunk
    },
    dispose: async () => {},
  }
}

type WireOptions = { headers: Record<string, string> }
type WireModel = { baseUrl: string }

function scripted(scripts: PiEvent[][], delegate?: DelegationDelegate | null) {
  const calls: Array<{ model: WireModel; options: WireOptions }> = []
  const adapter = new ZenAdapter(
    {
      list: () => [options.model],
      decision: () => ({ allowed: true, known: true, source: 'test' }),
      reasoningCapability: () => ({ reasoning: false, effortValues: [] }),
    },
    {
      delegate: delegate ?? null,
      providerOverride: {
        streamSimple(model: unknown, _context: unknown, wireOptions: WireOptions) {
          const events = scripts[calls.length]
          assert.ok(events, 'unexpected extra request')
          calls.push({ model: model as WireModel, options: wireOptions })
          return (async function* (): AsyncGenerator<PiEvent> {
            for (const event of events) yield event
          })()
        },
      },
    },
  )
  return { adapter, calls }
}

async function collect(adapter: ZenAdapter): Promise<HarnessChunk[]> {
  const chunks: HarnessChunk[] = []
  for await (const chunk of adapter.stream(options)) chunks.push(chunk)
  return chunks
}

test('isFreeTierRefusal matches the credential gate and nothing else', () => {
  assert.equal(isFreeTierRefusal('403 FreeTierError: free tier can only be used from within OpenCode'), true)
  assert.equal(isFreeTierRefusal("FreeTierError: OpenCode's free tier can only be used from within OpenCode"), true)
  assert.equal(isFreeTierRefusal('403 RegionError: not available in your country'), false)
  assert.equal(isFreeTierRefusal('429 rate limit exceeded'), false)
  assert.equal(isFreeTierRefusal('connection reset'), false)
})

test('isFreeTierRefusal also matches the free-lane quota spellings (folded lib patch)', () => {
  assert.equal(isFreeTierRefusal('429 FreeUsageLimitError: free usage limit reached'), true)
  assert.equal(isFreeTierRefusal('429 free usage limit reached'), true)
  // A generic 429 with neither spelling is still NOT a delegation-class refusal.
  assert.equal(isFreeTierRefusal('429 Too Many Requests'), false)
})

test('delegation off: persistent refusal surfaces the honest error and never consults a delegate', async () => {
  const { adapter, calls } = scripted([freeTierRefused(), freeTierRefused()])
  const chunks = await collect(adapter)

  assert.equal(calls.length, 2, 'direct + sibling replay, then give up')
  const finish = chunks.at(-1)
  assert.equal(finish?.type, 'finish')
  if (finish?.type === 'finish') assert.equal(finish.reason.kind, 'error')
  const text = chunks.filter((chunk) => chunk.type === 'text-delta')
  assert.equal(text.length, 0, 'no delegated content leaks onto the anonymous path')
})

test('delegation on: a persistent FreeTierError refusal runs the turn through the delegate', async () => {
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ chunks: delegateChunks }, calls)
  const { adapter, calls: wire } = scripted([freeTierRefused(), freeTierRefused()], delegate)
  const chunks = await collect(adapter)

  assert.equal(wire.length, 2, 'direct + sibling both refused before delegating')
  assert.equal(calls.ready, 1, 'delegate readiness probed once')
  assert.equal(calls.stream, 1, 'exactly one delegated turn')
  assert.deepEqual(chunks, delegateChunks, 'the delegated stream is what the user sees')
})

test('delegation on: a 429 FreeUsageLimitError delegates on the FIRST attempt (folded lib patch)', async () => {
  // Quota failures classify as 'limited', never 'refused', so the sibling
  // replay never fires for them — with the old `attempt >= 1` guard the
  // delegate was unreachable. `attempt >= 0` (folded into source) fixes that.
  const quotaRefused: PiEvent[] = [{
    type: 'error',
    error: message({
      stopReason: 'error',
      content: [],
      errorMessage: '429 FreeUsageLimitError: free usage limit reached',
      usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0 },
    }),
  }]
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ chunks: delegateChunks }, calls)
  const { adapter, calls: wire } = scripted([quotaRefused], delegate)
  const chunks = await collect(adapter)

  assert.equal(wire.length, 1, 'no sibling replay for a quota failure — straight to delegation')
  assert.equal(calls.stream, 1, 'exactly one delegated turn')
  assert.deepEqual(chunks, delegateChunks, 'the delegated stream is what the user sees')
})

test('delegation on but no credential (ready=false) falls back to the honest error', async () => {
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ ready: false }, calls)
  const { adapter, calls: wire } = scripted([freeTierRefused(), freeTierRefused()], delegate)
  const chunks = await collect(adapter)

  assert.equal(wire.length, 2)
  assert.equal(calls.ready, 1)
  assert.equal(calls.stream, 0, 'a disarmed delegate never runs a turn')
  const finish = chunks.at(-1)
  if (finish?.type === 'finish') assert.equal(finish.reason.kind, 'error')
})

test('delegation on but the delegated turn fails: fall back to the honest error, never partial content', async () => {
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ error: new Error('opencode exited') }, calls)
  const { adapter, calls: wire } = scripted([freeTierRefused(), freeTierRefused()], delegate)
  const chunks = await collect(adapter)

  assert.equal(wire.length, 2)
  assert.equal(calls.stream, 1)
  const finish = chunks.at(-1)
  if (finish?.type === 'finish') assert.equal(finish.reason.kind, 'error')
  assert.equal(chunks.some((chunk) => chunk.type === 'text-delta'), false, 'a failed delegation leaves no partial text behind')
})

test('a region refusal is NOT delegated even with an armed delegate', async () => {
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ chunks: delegateChunks }, calls)
  const { adapter, calls: wire } = scripted([regionRefused(), regionRefused()], delegate)
  const chunks = await collect(adapter)

  assert.equal(wire.length, 2)
  assert.equal(calls.ready, 0, 'only the FreeTierError class arms the delegate')
  assert.equal(calls.stream, 0)
  const finish = chunks.at(-1)
  if (finish?.type === 'finish') assert.equal(finish.reason.kind, 'error')
})

test('a refusal that recovers on the sibling replay is not a persistent refusal: no delegation', async () => {
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ chunks: delegateChunks }, calls)
  const { adapter, calls: wire } = scripted([freeTierRefused(), answered()], delegate)
  const chunks = await collect(adapter)

  assert.equal(wire.length, 2, 'the sibling replay answered, so the anonymous lane recovered')
  assert.equal(calls.ready, 0, 'no persistent refusal -> delegate stays out of the path')
  assert.equal(calls.stream, 0)
  assert.deepEqual(chunks.at(-1), { type: 'finish', reason: { kind: 'stop' } })
})

test('a single attempt never reaches delegation (the sibling is always tried first)', async () => {
  const calls = { ready: 0, stream: 0 }
  const delegate = fakeDelegate({ chunks: delegateChunks }, calls)
  // Only one script: any second provider call would fail the assert in streamSimple.
  const { adapter } = scripted([freeTierRefused(), answered()], delegate)
  const chunks = await collect(adapter)
  assert.equal(calls.stream, 0)
  assert.deepEqual(chunks.at(-1), { type: 'finish', reason: { kind: 'stop' } })
})
