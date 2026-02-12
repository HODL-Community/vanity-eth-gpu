import { bytesToHex, hexToBytes, nowMs } from '../utils/hex'
import { type SearchTarget } from '../searchTarget'
import { createWorkerPool, type WorkerPool } from '../worker/pool'
import { createGpuMatcher, type GpuMatcher } from '../webgpu/gpuMatcher'
import { keypairArrayFromPriv, secretKeyBase58FromPriv } from '../wallet/keypairJson'
import { type PrivKey32 } from '../wallet/keys'
import {
  BASE58_ALPHABET,
  bytesToBase58,
  hasCaseInsensitiveVariant,
  matchesVanityTarget,
  sanitizeBase58Input,
} from '../wallet/solanaAddress'

type Backend = 'gpu' | 'cpu'

type RunState =
  | { status: 'idle' }
  | { status: 'running'; startedAtMs: number; generated: number; speed: number }
  | { status: 'found'; generated: number; time: number; foundPriv: PrivKey32; foundAddress: string }

const PREVIEW_LENGTH = 44
let cachedBackend: Backend | null = null

function forcedBackendFromEnv(): Backend | null {
  const value = import.meta.env.VITE_FORCE_BACKEND?.trim().toLowerCase()
  if (value === 'gpu') return 'gpu'
  if (value === 'cpu') return 'cpu'
  return null
}

function formatNumber(n: number): string {
  if (n >= 1e12) return (n / 1e12).toFixed(1) + 'T'
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B'
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M'
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K'
  return n.toLocaleString()
}

function formatTime(seconds: number): string {
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`
  if (seconds < 86400) return `${(seconds / 3600).toFixed(1)}h`
  if (seconds < 31536000) return `${(seconds / 86400).toFixed(1)}d`
  return `${(seconds / 31536000).toFixed(1)}y`
}

function calculateDifficulty(prefix: string, suffix: string, caseSensitive: boolean): number {
  const pattern = prefix + suffix
  if (pattern.length === 0) return 1

  let difficulty = Math.pow(58, pattern.length)
  if (!caseSensitive) {
    let variants = 1
    for (const ch of pattern) {
      if (hasCaseInsensitiveVariant(ch)) variants *= 2
    }
    difficulty = difficulty / variants
  }

  return Math.max(1, difficulty)
}

function estimateTime(difficulty: number, speed: number): string {
  if (speed === 0) return '-'
  const avgAttempts = difficulty / 2
  const seconds = avgAttempts / speed
  return '~' + formatTime(seconds)
}

function targetPreviewLabel(target: SearchTarget): string {
  return target === 'program' ? 'Program ID Preview' : 'Wallet Address Preview'
}

function targetResultLabel(target: SearchTarget): string {
  return target === 'program' ? 'Program ID' : 'Wallet Address'
}

function generateNoise(len: number, offset: number): string {
  let result = ''
  for (let i = 0; i < len; i++) {
    result += BASE58_ALPHABET[(i + offset * 13) % BASE58_ALPHABET.length]
  }
  return result
}

async function copyToClipboard(text: string, btn: HTMLButtonElement) {
  try {
    await navigator.clipboard.writeText(text)
    btn.textContent = 'Copied!'
    btn.classList.add('copied')
    setTimeout(() => {
      btn.textContent = 'Copy'
      btn.classList.remove('copied')
    }, 1500)
  } catch {
    btn.textContent = 'Failed'
    setTimeout(() => {
      btn.textContent = 'Copy'
    }, 1500)
  }
}

function setInputsDisabled(
  disabled: boolean,
  prefixInput: HTMLInputElement,
  suffixInput: HTMLInputElement,
  searchTargetInputs: HTMLInputElement[],
  caseSensitiveInput: HTMLInputElement,
) {
  prefixInput.disabled = disabled
  suffixInput.disabled = disabled
  for (const input of searchTargetInputs) input.disabled = disabled
  caseSensitiveInput.disabled = disabled
}

export function initApp(root: HTMLDivElement) {
  root.innerHTML = `
    <div class="header">
      <div class="logo">
        <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
          <defs>
            <linearGradient id="sol-glyph-gradient" x1="0" y1="0" x2="1" y2="1">
              <stop offset="0%" stop-color="#14f195"/>
              <stop offset="100%" stop-color="#9945ff"/>
            </linearGradient>
          </defs>
          <path d="M20 24H84L74 35H10L20 24Z" fill="url(#sol-glyph-gradient)"/>
          <path d="M10 47H74L64 58H0L10 47Z" fill="url(#sol-glyph-gradient)"/>
          <path d="M20 70H84L74 81H10L20 70Z" fill="url(#sol-glyph-gradient)"/>
        </svg>
      </div>
      <div class="title">Vanity SOL GPU</div>
      <div class="subtitle" id="subtitle">Fast Solana vanity address generator</div>
    </div>

    <div class="panel">
      <div class="preview" id="preview">
        <div class="preview-label" id="preview-label">Wallet Address Preview</div>
        <div class="preview-address" id="preview-addr"></div>
      </div>

      <div class="input-group">
        <div class="field">
          <label for="prefix">Prefix</label>
          <input type="text" id="prefix" placeholder="Sol" spellcheck="false" autocomplete="off">
        </div>
        <div class="field">
          <label for="suffix">Suffix</label>
          <input type="text" id="suffix" placeholder="pump" spellcheck="false" autocomplete="off">
        </div>
      </div>

      <div class="options">
        <div class="target-wrap">
          <div class="target-label">Target</div>
          <div class="target-toggle" role="radiogroup" aria-label="Search target">
            <label class="target-option">
              <input type="radio" name="search-target" value="wallet" checked>
              <span>Wallet</span>
            </label>
            <label class="target-option">
              <input type="radio" name="search-target" value="program">
              <span>Program ID</span>
            </label>
          </div>
        </div>
        <div class="case-wrap">
          <div class="target-label">Match</div>
          <div class="case-toggle">
            <label class="case-option">
              <input type="checkbox" id="case-sensitive" checked>
              <span>Case-sensitive</span>
            </label>
          </div>
        </div>
      </div>

      <button class="btn-generate" id="btn-generate">Generate</button>

      <div class="stats">
        <div class="stat">
          <div class="stat-label">Speed</div>
          <div class="stat-value" id="stat-speed">-</div>
        </div>
        <div class="stat">
          <div class="stat-label">Checked</div>
          <div class="stat-value" id="stat-checked">0</div>
        </div>
        <div class="stat">
          <div class="stat-label">Est. Time</div>
          <div class="stat-value" id="stat-eta">-</div>
        </div>
      </div>

      <div class="result" id="result">
        <div class="result-row">
          <div class="result-label" id="result-addr-label">Address</div>
          <div class="result-value" id="result-addr">
            <span id="addr-text"></span>
            <button class="copy-btn" id="copy-addr">Copy</button>
          </div>
        </div>
        <div class="result-row">
          <div class="result-label">Secret Key (base58)</div>
          <div class="result-value" id="result-sk">
            <span id="pk-text"></span>
            <button class="copy-btn hidden" id="copy-pk">Copy</button>
          </div>
        </div>
        <div class="actions">
          <button class="btn" id="btn-reveal">Reveal Key</button>
          <button class="btn btn-primary" id="btn-download">Download Keypair JSON</button>
        </div>
      </div>
    </div>

    <div class="footer">
      <div>All computations run locally in your browser. For maximum security, disconnect from the internet before generating.</div>
      <div class="built-by">Built by <a href="https://x.com/snapss" target="_blank" rel="noopener">@snapss</a> & <a href="https://claude.ai" target="_blank" rel="noopener">Claude</a></div>
      <div class="open-source"><a href="https://github.com/HODL-Community/vanity-sol-gpu" target="_blank" rel="noopener">Open Source</a> on GitHub</div>
    </div>
  `

  const prefixInput = root.querySelector<HTMLInputElement>('#prefix')!
  const suffixInput = root.querySelector<HTMLInputElement>('#suffix')!
  const searchTargetInputs = Array.from(root.querySelectorAll<HTMLInputElement>('input[name="search-target"]'))
  const caseSensitiveInput = root.querySelector<HTMLInputElement>('#case-sensitive')!
  const previewEl = root.querySelector<HTMLDivElement>('#preview')!
  const previewLabel = root.querySelector<HTMLDivElement>('#preview-label')!
  const previewAddr = root.querySelector<HTMLDivElement>('#preview-addr')!
  const btnGenerate = root.querySelector<HTMLButtonElement>('#btn-generate')!
  const statSpeed = root.querySelector<HTMLDivElement>('#stat-speed')!
  const statChecked = root.querySelector<HTMLDivElement>('#stat-checked')!
  const statEta = root.querySelector<HTMLDivElement>('#stat-eta')!
  const resultEl = root.querySelector<HTMLDivElement>('#result')!
  const resultAddrLabel = root.querySelector<HTMLDivElement>('#result-addr-label')!
  const addrText = root.querySelector<HTMLSpanElement>('#addr-text')!
  const pkText = root.querySelector<HTMLSpanElement>('#pk-text')!
  const copyAddr = root.querySelector<HTMLButtonElement>('#copy-addr')!
  const copyPk = root.querySelector<HTMLButtonElement>('#copy-pk')!
  const btnReveal = root.querySelector<HTMLButtonElement>('#btn-reveal')!
  const btnDownload = root.querySelector<HTMLButtonElement>('#btn-download')!
  const subtitleEl = root.querySelector<HTMLDivElement>('#subtitle')!

  let runState: RunState = { status: 'idle' }
  let stopRequested = false
  let lastFound: { priv: PrivKey32; targetAddress: string; target: SearchTarget } | null = null

  function selectedTarget(): SearchTarget {
    const checked = searchTargetInputs.find(input => input.checked)
    return checked?.value === 'program' ? 'program' : 'wallet'
  }

  function updateTargetLabels() {
    const target = selectedTarget()
    previewLabel.textContent = targetPreviewLabel(target)
  }

  function updatePreview() {
    updateTargetLabels()

    const prefix = sanitizeBase58Input(prefixInput.value)
    const suffix = sanitizeBase58Input(suffixInput.value)
    prefixInput.value = prefix
    suffixInput.value = suffix

    if (prefix.length + suffix.length > PREVIEW_LENGTH) {
      previewAddr.textContent = 'Prefix + suffix must be 44 chars or less'
      statEta.textContent = 'Invalid'
      return
    }

    const midLen = PREVIEW_LENGTH - prefix.length - suffix.length
    const mid = midLen > 0 ? generateNoise(midLen, prefix.length) : ''

    if (prefix.length + suffix.length === 0) {
      previewAddr.innerHTML = generateNoise(PREVIEW_LENGTH, 0)
      statEta.textContent = '-'
      return
    }

    previewAddr.innerHTML = `<span class="match">${prefix}</span>${mid}<span class="match">${suffix}</span>`

    const difficulty = calculateDifficulty(prefix, suffix, caseSensitiveInput.checked)
    if (runState.status === 'running' && runState.speed > 0) {
      statEta.textContent = estimateTime(difficulty, runState.speed)
    } else {
      statEta.textContent = `1 in ${formatNumber(difficulty)}`
    }
  }

  function updateStats() {
    if (runState.status === 'running') {
      statSpeed.textContent = formatNumber(runState.speed) + '/s'
      statChecked.textContent = formatNumber(runState.generated)

      const prefix = sanitizeBase58Input(prefixInput.value)
      const suffix = sanitizeBase58Input(suffixInput.value)
      const difficulty = calculateDifficulty(prefix, suffix, caseSensitiveInput.checked)
      statEta.textContent = estimateTime(difficulty, runState.speed)
      return
    }

    if (runState.status === 'found') {
      statChecked.textContent = formatNumber(runState.generated)
      statEta.textContent = `Found in ${formatTime(runState.time)}`
    }
  }

  async function benchmarkBackend(pool: WorkerPool): Promise<{ backend: Backend; gpuMatcher: GpuMatcher | null }> {
    if (cachedBackend === 'cpu') {
      return { backend: 'cpu', gpuMatcher: null }
    }

    let gpuMatcher: GpuMatcher | null = null
    try {
      gpuMatcher = await createGpuMatcher()
    } catch {
      cachedBackend = 'cpu'
      return { backend: 'cpu', gpuMatcher: null }
    }

    const BENCH_DURATION_MS = 1200
    const BENCH_BATCH_SIZE = 1024
    const impossiblePrefix = 'zzzzzzzzzzzzzz'
    const impossibleSuffix = 'zzzzzzzzzz'

    let gpuChecked = 0
    subtitleEl.textContent = 'Benchmarking GPU...'
    const gpuStart = nowMs()

    while (nowMs() - gpuStart < BENCH_DURATION_MS && !stopRequested) {
      const batches = []
      for (let i = 0; i < pool.workerCount; i++) {
        batches.push(pool.generate(BENCH_BATCH_SIZE))
      }

      const generated = await Promise.all(batches)

      for (const batch of generated) {
        await gpuMatcher.findMatchIndex(batch.pubKeys, batch.checked, impossiblePrefix, impossibleSuffix, true)
        gpuChecked += batch.checked
      }
    }

    if (stopRequested) {
      gpuMatcher.destroy()
      return { backend: 'cpu', gpuMatcher: null }
    }

    let cpuChecked = 0
    subtitleEl.textContent = 'Benchmarking CPU...'
    const cpuStart = nowMs()

    while (nowMs() - cpuStart < BENCH_DURATION_MS && !stopRequested) {
      const searches = []
      for (let i = 0; i < pool.workerCount; i++) {
        searches.push(pool.search(impossiblePrefix, impossibleSuffix, BENCH_BATCH_SIZE, 'wallet', true))
      }

      const results = await Promise.all(searches)
      for (const result of results) cpuChecked += result.checked
    }

    if (stopRequested) {
      gpuMatcher.destroy()
      return { backend: 'cpu', gpuMatcher: null }
    }

    const gpuSpeed = gpuChecked / Math.max((nowMs() - gpuStart) / 1000, 0.001)
    const cpuSpeed = cpuChecked / Math.max((nowMs() - cpuStart) / 1000, 0.001)

    const winner: Backend = gpuSpeed > cpuSpeed ? 'gpu' : 'cpu'
    cachedBackend = winner

    if (winner === 'cpu') {
      gpuMatcher.destroy()
      subtitleEl.textContent = `GPU: ${formatNumber(Math.round(gpuSpeed))}/s | CPU: ${formatNumber(Math.round(cpuSpeed))}/s → Using CPU`
      await new Promise(resolve => setTimeout(resolve, 1200))
      return { backend: 'cpu', gpuMatcher: null }
    }

    subtitleEl.textContent = `GPU: ${formatNumber(Math.round(gpuSpeed))}/s | CPU: ${formatNumber(Math.round(cpuSpeed))}/s → Using GPU`
    await new Promise(resolve => setTimeout(resolve, 1200))
    return { backend: 'gpu', gpuMatcher }
  }

  async function runCpuBackend(
    pool: WorkerPool,
    prefix: string,
    suffix: string,
    target: SearchTarget,
    caseSensitive: boolean
  ) {
    const batchPerWorker = 2048
    subtitleEl.textContent = `Running on CPU (${pool.workerCount} workers)`

    let recentGenerated = 0
    let recentStartMs = nowMs()

    while (!stopRequested && runState.status === 'running') {
      const searches = []
      for (let i = 0; i < pool.workerCount; i++) {
        searches.push(pool.search(prefix, suffix, batchPerWorker, target, caseSensitive))
      }

      const results = await Promise.all(searches)
      let totalChecked = 0

      for (const result of results) {
        totalChecked += result.checked
        if (result.found && runState.status === 'running') {
          handleFound(result.found.privHex, result.found.address, prefix, suffix, target, caseSensitive)
        }
      }

      if (runState.status === 'running') {
        runState = { ...runState, generated: runState.generated + totalChecked }
      }
      recentGenerated += totalChecked

      const elapsed = nowMs() - recentStartMs
      if (elapsed >= 500 && runState.status === 'running') {
        const speed = Math.floor(recentGenerated / (elapsed / 1000))
        runState = { ...runState, speed }
        recentGenerated = 0
        recentStartMs = nowMs()
        updateStats()
      }
    }
  }

  async function runGpuBackend(
    pool: WorkerPool,
    gpuMatcher: GpuMatcher,
    prefix: string,
    suffix: string,
    target: SearchTarget,
    caseSensitive: boolean
  ) {
    const batchPerWorker = 1024
    subtitleEl.textContent = `Running on GPU + CPU keygen (${pool.workerCount} workers)`

    let recentGenerated = 0
    let recentStartMs = nowMs()

    while (!stopRequested && runState.status === 'running') {
      const generatedBatches = []
      for (let i = 0; i < pool.workerCount; i++) {
        generatedBatches.push(pool.generate(batchPerWorker))
      }

      const batches = await Promise.all(generatedBatches)
      let totalChecked = 0

      for (const batch of batches) {
        totalChecked += batch.checked

        if (runState.status !== 'running') break

        const matchIndex = await gpuMatcher.findMatchIndex(
          batch.pubKeys,
          batch.checked,
          prefix,
          suffix,
          caseSensitive,
        )

        if (matchIndex === null || runState.status !== 'running') continue

        const privOffset = matchIndex * 32
        const priv = batch.privKeys.subarray(privOffset, privOffset + 32)
        const pub = batch.pubKeys.subarray(privOffset, privOffset + 32)

        handleFound(bytesToHex(priv), bytesToBase58(pub), prefix, suffix, target, caseSensitive)
      }

      if (runState.status === 'running') {
        runState = { ...runState, generated: runState.generated + totalChecked }
      }
      recentGenerated += totalChecked

      const elapsed = nowMs() - recentStartMs
      if (elapsed >= 500 && runState.status === 'running') {
        const speed = Math.floor(recentGenerated / (elapsed / 1000))
        runState = { ...runState, speed }
        recentGenerated = 0
        recentStartMs = nowMs()
        updateStats()
      }
    }
  }

  async function run() {
    stopRequested = false
    btnGenerate.textContent = 'Stop'
    btnGenerate.classList.add('running')
    previewEl.classList.add('generating')
    resultEl.classList.remove('visible', 'found')
    copyPk.classList.add('hidden')
    lastFound = null

    setInputsDisabled(true, prefixInput, suffixInput, searchTargetInputs, caseSensitiveInput)

    const prefix = sanitizeBase58Input(prefixInput.value)
    const suffix = sanitizeBase58Input(suffixInput.value)
    const target = selectedTarget()
    const caseSensitive = caseSensitiveInput.checked

    if (prefix.length + suffix.length === 0 || prefix.length + suffix.length > PREVIEW_LENGTH) {
      setInputsDisabled(false, prefixInput, suffixInput, searchTargetInputs, caseSensitiveInput)
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      return
    }

    const pool = createWorkerPool()
    let gpuMatcher: GpuMatcher | null = null
    const forcedBackend = forcedBackendFromEnv()
    let backend: Backend = forcedBackend ?? cachedBackend ?? 'cpu'

    const startedAtMs = nowMs()
    runState = { status: 'running', startedAtMs, generated: 0, speed: 0 }

    try {
      if (!forcedBackend && cachedBackend === null) {
        const benchmark = await benchmarkBackend(pool)
        backend = benchmark.backend
        gpuMatcher = benchmark.gpuMatcher
      }

      if (stopRequested || runState.status !== 'running') return

      if (backend === 'gpu' && !gpuMatcher) {
        try {
          gpuMatcher = await createGpuMatcher()
        } catch {
          backend = 'cpu'
          if (!forcedBackend) cachedBackend = 'cpu'
          subtitleEl.textContent = 'GPU unavailable, falling back to CPU'
          await new Promise(resolve => setTimeout(resolve, 1000))
        }
      }

      if (backend === 'gpu' && gpuMatcher) {
        await runGpuBackend(pool, gpuMatcher, prefix, suffix, target, caseSensitive)
      } else {
        await runCpuBackend(pool, prefix, suffix, target, caseSensitive)
      }
    } finally {
      pool.destroy()
      gpuMatcher?.destroy()

      setInputsDisabled(false, prefixInput, suffixInput, searchTargetInputs, caseSensitiveInput)

      const finalStatus = (runState as RunState).status
      if (finalStatus !== 'found') {
        runState = { status: 'idle' }
        subtitleEl.textContent = 'Fast Solana vanity address generator'
      }

      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
    }
  }

  function handleFound(
    privHex: string,
    foundAddress: string,
    prefix: string,
    suffix: string,
    target: SearchTarget,
    caseSensitive: boolean
  ) {
    if (!matchesVanityTarget(foundAddress, prefix, suffix, caseSensitive)) return

    const priv = hexToBytes(privHex) as PrivKey32
    const timeS = runState.status === 'running' ? (nowMs() - runState.startedAtMs) / 1000 : 0
    const generated = runState.status === 'running' ? runState.generated : 0

    runState = { status: 'found', generated, time: timeS, foundPriv: priv, foundAddress }
    lastFound = { priv, targetAddress: foundAddress, target }

    resultAddrLabel.textContent = targetResultLabel(target)

    const preMatch = foundAddress.slice(0, prefix.length)
    const sufMatch = suffix.length > 0 ? foundAddress.slice(foundAddress.length - suffix.length) : ''
    const midEnd = suffix.length > 0 ? foundAddress.length - suffix.length : foundAddress.length
    const mid = foundAddress.slice(prefix.length, midEnd)

    addrText.innerHTML = `<span class="highlight">${preMatch}</span>${mid}<span class="highlight">${sufMatch}</span>`
    pkText.textContent = '\u2022'.repeat(88)

    resultEl.classList.add('visible', 'found')
    subtitleEl.textContent = 'Match found'
    updateStats()
    stopRequested = true
  }

  prefixInput.addEventListener('input', () => {
    prefixInput.value = sanitizeBase58Input(prefixInput.value)
    updatePreview()
  })

  suffixInput.addEventListener('input', () => {
    suffixInput.value = sanitizeBase58Input(suffixInput.value)
    updatePreview()
  })

  for (const input of searchTargetInputs) {
    input.addEventListener('change', () => {
      updatePreview()
    })
  }

  caseSensitiveInput.addEventListener('change', () => {
    updatePreview()
  })

  btnGenerate.addEventListener('click', () => {
    if (runState.status === 'running') {
      stopRequested = true
    } else {
      void run()
    }
  })

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && document.activeElement?.tagName !== 'BUTTON') {
      e.preventDefault()
      btnGenerate.click()
    }
  })

  btnReveal.addEventListener('click', () => {
    if (!lastFound) return
    pkText.textContent = secretKeyBase58FromPriv(lastFound.priv)
    copyPk.classList.remove('hidden')
  })

  copyAddr.addEventListener('click', () => {
    if (!lastFound) return
    void copyToClipboard(lastFound.targetAddress, copyAddr)
  })

  copyPk.addEventListener('click', () => {
    if (!lastFound || !pkText.textContent || pkText.textContent.includes('\u2022')) return
    void copyToClipboard(pkText.textContent, copyPk)
  })

  btnDownload.addEventListener('click', () => {
    if (!lastFound) return

    const keypair = keypairArrayFromPriv(lastFound.priv)
    const blob = new Blob([JSON.stringify(keypair, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${lastFound.targetAddress}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  })

  updatePreview()
}
