import { bytesToHex, hexToBytes, nowMs } from '../utils/hex'
import { createKeystoreV3, type KeystoreV3 } from '../wallet/keystoreV3'
import { checksumAddress, pubkeyToAddressBytes, firstContractAddressFromWalletHex } from '../wallet/ethAddress'
import { privateKeyToPublicKey64, type PrivKey32 } from '../wallet/keys'
import { createWorkerPool } from '../worker/pool'
import { createWasmWorkerPool, type WasmWorkerPool } from '../worker/wasmPool'
import { createGpuVanityPool } from '../webgpu/gpuVanity'
import { type SearchTarget, searchTargetToGpuMode } from '../searchTarget'

// Benchmark cache: once determined, reuse the winner for the session
let cachedBackend: 'gpu' | 'wasm' | 'cpu' | null = null

type RunState =
  | { status: 'idle' }
  | { status: 'running'; startedAtMs: number; generated: number; speed: number }
  | { status: 'found'; generated: number; time: number; foundPriv: PrivKey32; foundAddress: string }

function sanitizeHex(s: string): string {
  return s.trim().replace(/^0x/i, '').replace(/[^0-9a-fA-F]/g, '').slice(0, 40)
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

function countLetters(s: string): number {
  return (s.match(/[a-fA-F]/g) || []).length
}

function calculateDifficulty(prefix: string, suffix: string, caseSensitive: boolean): number {
  const base = Math.pow(16, prefix.length + suffix.length)
  if (!caseSensitive) return base
  // Case-sensitive mode adds one binary constraint per alpha nibble.
  const letters = countLetters(prefix) + countLetters(suffix)
  return base * Math.pow(2, letters)
}

function estimateTime(difficulty: number, speed: number): string {
  if (speed === 0) return '-'
  // The search is memoryless, so report the MEDIAN time (50% chance of a hit by
  // then) rather than a mean that reads like a deadline. Median attempts = D·ln2.
  const seconds = (difficulty * Math.LN2) / speed
  return '~' + formatTime(seconds) + ' (50%)'
}

// Probability that at least one match has been found after `generated` attempts.
function chanceFoundByNow(difficulty: number, generated: number): number {
  if (difficulty <= 0) return 1
  return 1 - Math.exp(-generated / difficulty)
}

function targetPreviewLabel(target: SearchTarget): string {
  return target === 'first-contract' ? 'First Contract Address Preview' : 'Wallet Address Preview'
}

function targetResultLabel(target: SearchTarget): string {
  return target === 'first-contract' ? 'First Contract Address' : 'Wallet Address'
}

function deriveWalletAddressFromPriv(priv: PrivKey32): string {
  const pub64 = privateKeyToPublicKey64(priv)
  return '0x' + bytesToHex(pubkeyToAddressBytes(pub64))
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
    setTimeout(() => btn.textContent = 'Copy', 1500)
  }
}

export function initApp(root: HTMLDivElement) {
  root.innerHTML = `
    <div class="header">
      <div class="logo">
        <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <polygon points="12 2 2 12 12 22 22 12"/>
          <line x1="12" y1="2" x2="12" y2="12"/>
          <line x1="12" y1="12" x2="22" y2="12"/>
        </svg>
      </div>
      <div class="title">Vanity ETH GPU</div>
      <div class="subtitle" id="subtitle">Fast vanity address generator</div>
    </div>

    <div class="panel">
      <div class="preview" id="preview">
        <div class="preview-label" id="preview-label">Wallet Address Preview</div>
        <div class="preview-address" id="preview-addr"></div>
      </div>

      <div class="input-group">
        <div class="field">
          <label for="prefix">Prefix</label>
          <input type="text" id="prefix" placeholder="c0ffee" spellcheck="false" autocomplete="off">
        </div>
        <div class="field">
          <label for="suffix">Suffix</label>
          <input type="text" id="suffix" placeholder="beef" spellcheck="false" autocomplete="off">
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
              <input type="radio" name="search-target" value="first-contract">
              <span>Contract</span>
            </label>
          </div>
        </div>
        <div class="case-wrap">
          <div class="target-label">Checksum</div>
          <div class="case-toggle">
            <label class="case-option">
              <input type="checkbox" id="case-sensitive">
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
        <div class="result-row hidden" id="wallet-row">
          <div class="result-label">Deployer Wallet</div>
          <div class="result-value" id="result-wallet">
            <span id="wallet-text"></span>
            <button class="copy-btn" id="copy-wallet">Copy</button>
          </div>
        </div>
        <div class="result-row">
          <div class="result-label">Private Key</div>
          <div class="result-value" id="result-pk">
            <span id="pk-text"></span>
            <button class="copy-btn hidden" id="copy-pk">Copy</button>
          </div>
          <div class="copy-warning hidden" id="pk-warning">⚠ Anyone with this key controls all funds. Never paste it into a website or share it — clipboard contents can be read by other apps.</div>
        </div>
        <div class="actions">
          <button class="btn" id="btn-reveal">Reveal Key</button>
          <button class="btn btn-primary" id="btn-download">Download Keystore</button>
        </div>
        <div class="security-note">
          <strong>Before funding this address:</strong>
          <ul>
            <li>Verify the full address character-by-character.</li>
            <li>Reveal &amp; back up the private key or keystore offline.</li>
            <li>Send a tiny test amount first and confirm you control it.</li>
          </ul>
        </div>
      </div>
    </div>

    <div class="footer">
      <div>All computations run locally in your browser. For maximum security, disconnect from the internet before generating.</div>
      <div class="built-by">Built by <a href="https://x.com/snapss" target="_blank" rel="noopener">@snapss</a> & <a href="https://claude.ai" target="_blank" rel="noopener">Claude</a></div>
      <div class="open-source"><a href="https://github.com/HODL-Community/vanity-eth-gpu" target="_blank" rel="noopener">Open Source</a> on GitHub</div>
      <div class="donate">Donate: <span class="donate-addr">0x99999933F17A1339958d50b3f59740E5Ad48C74C</span><button class="copy-btn-small" id="copy-donate">Copy</button></div>
    </div>

    <div class="modal-overlay" id="pw-modal" hidden>
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="pw-modal-title">
        <div class="modal-title" id="pw-modal-title">Encrypt Keystore</div>
        <div class="modal-desc">Choose a password to encrypt your private key. You'll need this exact password to import the keystore — there is no recovery if you lose it.</div>
        <input type="password" id="pw-input" class="modal-input" placeholder="Password (min 8 characters)" autocomplete="new-password" spellcheck="false">
        <input type="password" id="pw-confirm" class="modal-input" placeholder="Confirm password" autocomplete="new-password" spellcheck="false">
        <div class="modal-error" id="pw-error" aria-live="polite"></div>
        <div class="modal-actions">
          <button class="btn" id="pw-cancel">Cancel</button>
          <button class="btn btn-primary" id="pw-ok">Encrypt &amp; Download</button>
        </div>
      </div>
    </div>
  `

  // Elements
  const prefixInput = root.querySelector<HTMLInputElement>('#prefix')!
  const suffixInput = root.querySelector<HTMLInputElement>('#suffix')!
  const searchTargetInputs = Array.from(root.querySelectorAll<HTMLInputElement>('input[name="search-target"]'))
  const caseSensitive = root.querySelector<HTMLInputElement>('#case-sensitive')!
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
  const walletRow = root.querySelector<HTMLDivElement>('#wallet-row')!
  const walletText = root.querySelector<HTMLSpanElement>('#wallet-text')!
  const pkText = root.querySelector<HTMLSpanElement>('#pk-text')!
  const copyAddr = root.querySelector<HTMLButtonElement>('#copy-addr')!
  const copyWallet = root.querySelector<HTMLButtonElement>('#copy-wallet')!
  const copyPk = root.querySelector<HTMLButtonElement>('#copy-pk')!
  const btnReveal = root.querySelector<HTMLButtonElement>('#btn-reveal')!
  const btnDownload = root.querySelector<HTMLButtonElement>('#btn-download')!
  const subtitleEl = root.querySelector<HTMLDivElement>('#subtitle')!

  // State
  let runState: RunState = { status: 'idle' }
  let stopRequested = false
  let lastFound: { priv: PrivKey32; targetAddress: string; walletAddress: string; target: SearchTarget } | null = null

  // Count candidates discarded by the verification gate. A nonzero count during a
  // real search means a backend (almost always the GPU kernel on this device) is
  // miscomputing — surface it so the user isn't left waiting on a broken backend.
  let rejectedMatches = 0
  function noteRejectedMatch() {
    rejectedMatches++
    if (rejectedMatches === 1 || rejectedMatches % 100 === 0) {
      console.error(`[vanity] Discarded ${rejectedMatches} match(es) that failed CPU re-derivation — the active backend may be miscomputing addresses on this device.`)
    }
    if (rejectedMatches === 25) {
      subtitleEl.textContent = '⚠️ GPU produced invalid results — verifying on CPU. Try reloading if this persists.'
    }
  }

  // Cleanup for whatever backend pool is currently active, so an exception
  // mid-search (e.g. a lost GPU device) can release it instead of leaking.
  let activePoolCleanup: (() => void) | null = null
  function runActivePoolCleanup() {
    if (activePoolCleanup) {
      try { activePoolCleanup() } catch { /* ignore */ }
      activePoolCleanup = null
    }
  }
  // Return the UI to the idle state. Never clobbers a displayed 'found' result.
  function forceIdle() {
    runActivePoolCleanup()
    if (runState.status === 'found') return
    prefixInput.disabled = false
    suffixInput.disabled = false
    for (const input of searchTargetInputs) input.disabled = false
    caseSensitive.disabled = false
    btnGenerate.textContent = 'Generate'
    btnGenerate.classList.remove('running')
    previewEl.classList.remove('generating')
    runState = { status: 'idle' }
  }

  // Deterministic noise based on position (looks random but stable)
  const noiseChars = '7a3f8c2e9b1d5046'
  function generateNoise(len: number, offset: number): string {
    let result = ''
    for (let i = 0; i < len; i++) {
      result += noiseChars[(i + offset * 7) % noiseChars.length]
    }
    return result
  }

  function selectedTarget(): SearchTarget {
    const checked = searchTargetInputs.find(input => input.checked)
    return checked?.value === 'first-contract' ? 'first-contract' : 'wallet'
  }

  function updateTargetLabels() {
    const target = selectedTarget()
    previewLabel.textContent = targetPreviewLabel(target)
  }

  // Update preview
  function updatePreview() {
    updateTargetLabels()
    const pre = sanitizeHex(prefixInput.value)
    const suf = sanitizeHex(suffixInput.value)
    const preLower = pre.toLowerCase()
    const sufLower = suf.toLowerCase()
    const midLen = 40 - pre.length - suf.length
    const mid = midLen > 0 ? generateNoise(midLen, pre.length) : ''

    if (pre.length + suf.length === 0) {
      previewAddr.innerHTML = '0x' + generateNoise(40, 0)
    } else {
      previewAddr.innerHTML = `0x<span class="match">${preLower}</span>${mid}<span class="match">${sufLower}</span>`
    }

    // Update ETA based on difficulty
    const difficulty = calculateDifficulty(pre, suf, caseSensitive.checked)
    if (runState.status === 'running' && runState.speed > 0) {
      statEta.textContent = estimateTime(difficulty, runState.speed)
    } else if (pre.length + suf.length > 0) {
      statEta.textContent = `1 in ${formatNumber(difficulty)}`
    } else {
      statEta.textContent = '-'
    }
  }

  // Update stats display
  function updateStats() {
    if (runState.status === 'running') {
      statSpeed.textContent = formatNumber(runState.speed) + '/s'
      statChecked.textContent = formatNumber(runState.generated)
      const pre = sanitizeHex(prefixInput.value)
      const suf = sanitizeHex(suffixInput.value)
      const difficulty = calculateDifficulty(pre, suf, caseSensitive.checked)
      statEta.textContent = estimateTime(difficulty, runState.speed)
      // Surface the live "probability of a hit by now" so a long-but-normal run
      // doesn't feel broken — it's a memoryless process, not a countdown.
      const pct = Math.round(chanceFoundByNow(difficulty, runState.generated) * 100)
      statEta.title = `${pct}% chance of a match by now (median ETA shown)`
    } else if (runState.status === 'found') {
      statEta.title = ''
      statChecked.textContent = formatNumber(runState.generated)
      statEta.textContent = `Found in ${formatTime(runState.time)}`
    }
  }

  // Convert hex string to nibble array (each hex char → number 0-15)
  function hexToNibbles(hex: string): number[] {
    return hex.split('').map(c => parseInt(c, 16))
  }

  // Main generation loop - auto-benchmarks GPU vs CPU on first run
  async function run() {
    stopRequested = false
    rejectedMatches = 0
    btnGenerate.textContent = 'Stop'
    btnGenerate.classList.add('running')
    previewEl.classList.add('generating')
    resultEl.classList.remove('visible', 'found')
    walletRow.classList.add('hidden')
    walletText.textContent = ''
    maskKey()
    lastFound = null

    // Disable inputs while running
    prefixInput.disabled = true
    suffixInput.disabled = true
    for (const input of searchTargetInputs) input.disabled = true
    caseSensitive.disabled = true

    const pre = sanitizeHex(prefixInput.value)
    const suf = sanitizeHex(suffixInput.value)
    const preLower = pre.toLowerCase()
    const sufLower = suf.toLowerCase()
    const target = selectedTarget()

    if (pre.length + suf.length === 0) {
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      prefixInput.disabled = false
      suffixInput.disabled = false
      for (const input of searchTargetInputs) input.disabled = false
      caseSensitive.disabled = false
      return
    }

    // Helper to reset UI on early exit during benchmark
    function resetUI() {
      prefixInput.disabled = false
      suffixInput.disabled = false
      for (const input of searchTargetInputs) input.disabled = false
      caseSensitive.disabled = false
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      subtitleEl.textContent = 'Fast vanity address generator'
      runState = { status: 'idle' }
    }

    // An Ethereum address is 40 hex chars; a prefix+suffix longer than that can
    // never be satisfied, so don't start a futile, never-ending search.
    if (pre.length + suf.length > 40) {
      resetUI()
      subtitleEl.textContent = 'Prefix + suffix can be at most 40 hex characters total.'
      return
    }

    // ── Auto-benchmark on first run (GPU vs WASM vs CPU) ──
    if (cachedBackend === null) {
      const BENCH_DURATION_MS = 3000
      const BENCH_BATCH = 16384

      // Check if GPU is available at all
      let gpuAvailable = false
      let gpuCount = 0
      try {
        const testPool = await createGpuVanityPool()
        gpuCount = testPool.instances.length
        testPool.destroy()
        gpuAvailable = true
      } catch {
        // WebGPU not available
      }

      if (stopRequested) { resetUI(); return }

      let gpuSpeed = 0
      let wasmSpeed = 0
      let cpuSpeed = 0
      let wasmPool: WasmWorkerPool | null = null

      if (gpuAvailable) {
        // Benchmark all GPUs together (running in parallel) for a fair
        // comparison against the multi-worker WASM/CPU pools.
        subtitleEl.textContent = gpuCount > 1 ? `Benchmarking ${gpuCount} GPUs...` : 'Benchmarking GPU...'
        const dummyNibbles = [0, 0, 0, 0, 0, 0, 0, 0]
        const mode = searchTargetToGpuMode(target)
        let gpuChecked = 0
        const gpuPool = await createGpuVanityPool()
        gpuCount = gpuPool.instances.length
        const gpuStart = nowMs()
        while (nowMs() - gpuStart < BENCH_DURATION_MS && !stopRequested) {
          await Promise.all(gpuPool.instances.map(g =>
            g.search(dummyNibbles, dummyNibbles, BENCH_BATCH, mode)
          ))
          gpuChecked += BENCH_BATCH * gpuPool.instances.length
        }
        gpuSpeed = gpuChecked / ((nowMs() - gpuStart) / 1000)
        gpuPool.destroy()

        if (stopRequested) { resetUI(); return }
      }

      // Benchmark WASM (sequential init with timeout, won't hang)
      subtitleEl.textContent = 'Benchmarking WASM...'
      wasmPool = await createWasmWorkerPool(10000)

      if (wasmPool && !stopRequested) {
        let wasmChecked = 0
        const wasmStart = nowMs()
        while (nowMs() - wasmStart < BENCH_DURATION_MS && !stopRequested) {
          const promises = []
          for (let i = 0; i < wasmPool.workerCount; i++) {
            promises.push(wasmPool.search('00000000', '', BENCH_BATCH, target))
          }
          const results = await Promise.all(promises)
          for (const r of results) wasmChecked += r.checked
        }
        wasmSpeed = wasmChecked / ((nowMs() - wasmStart) / 1000)
        // Don't destroy yet — we might use it for the real search
      }

      if (stopRequested) {
        wasmPool?.destroy()
        resetUI()
        return
      }

      // Benchmark CPU
      subtitleEl.textContent = 'Benchmarking CPU...'
      let cpuChecked = 0
      const benchPool = createWorkerPool()
      const cpuStart = nowMs()
      while (nowMs() - cpuStart < BENCH_DURATION_MS && !stopRequested) {
        const promises = []
        for (let i = 0; i < benchPool.workerCount; i++) {
          promises.push(benchPool.search('00000000', '', BENCH_BATCH, target))
        }
        const results = await Promise.all(promises)
        for (const r of results) cpuChecked += r.checked
      }
      cpuSpeed = cpuChecked / ((nowMs() - cpuStart) / 1000)
      benchPool.destroy()

      if (stopRequested) {
        wasmPool?.destroy()
        resetUI()
        return
      }

      // Pick the winner
      const speeds: [string, number][] = []
      if (gpuAvailable) speeds.push(['gpu', gpuSpeed])
      if (wasmPool) speeds.push(['wasm', wasmSpeed])
      speeds.push(['cpu', cpuSpeed])
      speeds.sort((a, b) => b[1] - a[1])
      const winner = speeds[0][0] as 'gpu' | 'wasm' | 'cpu'
      cachedBackend = winner

      // Destroy WASM pool if it lost
      if (winner !== 'wasm') wasmPool?.destroy()

      // Show result for 2 seconds
      const parts: string[] = []
      if (gpuAvailable) parts.push(`GPU${gpuCount > 1 ? ` x${gpuCount}` : ''}: ${formatNumber(Math.round(gpuSpeed))}/s`)
      if (wasmPool) parts.push(`WASM: ${formatNumber(Math.round(wasmSpeed))}/s`)
      parts.push(`CPU: ${formatNumber(Math.round(cpuSpeed))}/s`)
      subtitleEl.textContent = `${parts.join(' | ')} → Using ${winner.toUpperCase()}`
      await new Promise(resolve => setTimeout(resolve, 2000))

      if (stopRequested) {
        if (winner === 'wasm') wasmPool?.destroy()
        resetUI()
        return
      }
    }

    // ── Start the real search ──
    const startedAtMs = nowMs()
    runState = { status: 'running', startedAtMs, generated: 0, speed: 0 }

    let recentGenerated = 0
    let recentStartMs = nowMs()

    if (cachedBackend === 'gpu') {
      // ── GPU path (one concurrent loop per physical GPU) ──
      const gpuPool = await createGpuVanityPool()
      activePoolCleanup = () => gpuPool.destroy()
      const gpuCount = gpuPool.instances.length
      subtitleEl.textContent = gpuCount > 1
        ? `Running on ${gpuCount} GPUs (${gpuPool.labels.join(', ')})`
        : `Running on GPU (${gpuPool.labels[0]})`
      const prefixNibbles = hexToNibbles(preLower)
      const suffixNibbles = hexToNibbles(sufLower)
      const gpuBatchSize = 16384
      const mode = searchTargetToGpuMode(target)

      // A single timer aggregates throughput; each GPU loop only bumps counters.
      const speedTimer = setInterval(() => {
        const elapsed = nowMs() - recentStartMs
        if (elapsed >= 500 && runState.status === 'running') {
          const speed = Math.floor(recentGenerated / (elapsed / 1000))
          runState = { ...runState, speed }
          recentGenerated = 0
          recentStartMs = nowMs()
          updateStats()
        }
      }, 250)

      try {
        // Each GPU runs its own search loop concurrently. They draw independent
        // random seeds, so no coordination is needed, and a match on any GPU
        // sets stopRequested, draining all loops.
        await Promise.all(gpuPool.instances.map(async (gpu) => {
          while (!stopRequested) {
            const result = await gpu.search(prefixNibbles, suffixNibbles, gpuBatchSize, mode)

            if (result && runState.status === 'running') {
              const foundAddress = checksumAddress(result.addressHex)
              handleFound(result.privHex, foundAddress, pre, suf, target)
            }

            if (runState.status === 'running') {
              runState = { ...runState, generated: runState.generated + gpuBatchSize }
            }
            recentGenerated += gpuBatchSize
          }
        }))
      } finally {
        clearInterval(speedTimer)
        gpuPool.destroy()
        activePoolCleanup = null
      }
    } else if (cachedBackend === 'wasm') {
      // ── WASM path (pool already initialized from benchmark) ──
      const pool = await createWasmWorkerPool(10000)
      if (!pool) {
        // Fallback to CPU if WASM init fails on second attempt
        cachedBackend = 'cpu'
        subtitleEl.textContent = 'WASM failed, falling back to CPU...'
        await new Promise(resolve => setTimeout(resolve, 1000))
      }

      if (pool && cachedBackend === 'wasm') {
        activePoolCleanup = () => pool.destroy()
        subtitleEl.textContent = `Running on WASM (${pool.workerCount} workers)`
        const batchPerWorker = 16384

        try {
          while (!stopRequested) {
            const promises = []
            for (let i = 0; i < pool.workerCount; i++) {
              promises.push(pool.search(preLower, sufLower, batchPerWorker, target))
            }

            const results = await Promise.all(promises)
            let totalChecked = 0

            for (const r of results) {
              totalChecked += r.checked
              if (r.found && runState.status === 'running') {
                const foundAddress = checksumAddress(r.found.address)
                handleFound(r.found.privHex, foundAddress, pre, suf, target)
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
        } finally {
          pool.destroy()
          activePoolCleanup = null
        }
      }
    }

    // CPU fallback (also handles WASM→CPU fallback)
    if (cachedBackend === 'cpu' && !stopRequested && runState.status === 'running') {
      // ── CPU path ──
      const pool = createWorkerPool()
      activePoolCleanup = () => pool.destroy()
      subtitleEl.textContent = `Running on CPU (${pool.workerCount} workers)`
      const batchPerWorker = 16384

      try {
        while (!stopRequested) {
          const promises = []
          for (let i = 0; i < pool.workerCount; i++) {
            promises.push(pool.search(preLower, sufLower, batchPerWorker, target))
          }

          const results = await Promise.all(promises)
          let totalChecked = 0

          for (const r of results) {
            totalChecked += r.checked
            if (r.found && runState.status === 'running') {
              const foundAddress = checksumAddress(r.found.address)
              handleFound(r.found.privHex, foundAddress, pre, suf, target)
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
      } finally {
        pool.destroy()
        activePoolCleanup = null
      }
    }

    // Re-enable inputs
    prefixInput.disabled = false
    suffixInput.disabled = false
    for (const input of searchTargetInputs) input.disabled = false
    caseSensitive.disabled = false

    if (!stopRequested || runState.status === 'running') {
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      subtitleEl.textContent = 'Fast vanity address generator'
      runState = { status: 'idle' }
    }
  }

  function handleFound(privHex: string, claimedAddress: string, pre: string, suf: string, target: SearchTarget) {
    // ── Verification gate ──
    // The GPU kernel is hand-rolled WGSL; never trust its (priv, address) pair.
    // Re-derive the address from the private key using the audited @noble path
    // and reject any candidate whose real address doesn't match what the backend
    // claimed. One EC derivation per *match* (matches are rare) — negligible cost,
    // but it removes the only catastrophic failure mode (funding an address whose
    // key you don't actually control). Applies to all three backends uniformly.
    let priv: PrivKey32
    let trustedWallet: string
    let trustedTarget: string
    try {
      priv = hexToBytes(privHex) as PrivKey32
      if (priv.length !== 32) throw new Error('bad key length')
      trustedWallet = deriveWalletAddressFromPriv(priv) // '0x' + lowercase 40 hex
      trustedTarget = target === 'first-contract'
        ? '0x' + firstContractAddressFromWalletHex(trustedWallet.slice(2))
        : trustedWallet
    } catch {
      // Invalid scalar (0 or >= curve order) or malformed hex — discard, keep searching.
      noteRejectedMatch()
      return
    }

    if (trustedTarget.toLowerCase() !== claimedAddress.toLowerCase()) {
      // Backend produced a (priv, address) pair that does NOT correspond under real
      // secp256k1 + keccak. Discard and keep searching (do not stop the run).
      noteRejectedMatch()
      return
    }

    // From here on, the noble-derived, EIP-55 checksummed address is the single
    // source of truth — displayed, copied, and used for the keystore filename.
    const foundAddress = checksumAddress(trustedTarget)
    const walletAddress = target === 'wallet' ? foundAddress : checksumAddress(trustedWallet)

    // Confirm it actually satisfies the requested prefix/suffix, applying the
    // case-sensitive (EIP-55) constraint when enabled.
    const preLower = pre.toLowerCase()
    const sufLower = suf.toLowerCase()
    const body = foundAddress.slice(2)
    const bodyLower = body.toLowerCase()
    const prefixOk = bodyLower.startsWith(preLower) && (!caseSensitive.checked || body.startsWith(pre))
    const suffixOk = bodyLower.endsWith(sufLower) && (!caseSensitive.checked || body.endsWith(suf))

    if (prefixOk && suffixOk) {
      const timeS = (nowMs() - (runState as any).startedAtMs) / 1000
      const generated: number = runState.status === 'running' ? runState.generated : 0

      runState = { status: 'found', generated, time: timeS, foundPriv: priv, foundAddress }
      lastFound = { priv, targetAddress: foundAddress, walletAddress, target }
      resultAddrLabel.textContent = targetResultLabel(target)

      const preMatch = foundAddress.slice(2, 2 + pre.length)
      const sufMatch = foundAddress.slice(2 + 40 - suf.length)
      const midPart = foundAddress.slice(2 + pre.length, 2 + 40 - suf.length)

      addrText.innerHTML = `0x<span class="highlight">${preMatch}</span>${midPart}<span class="highlight">${sufMatch}</span>`
      walletText.textContent = walletAddress
      if (target === 'first-contract') {
        walletRow.classList.remove('hidden')
      } else {
        walletRow.classList.add('hidden')
      }
      maskKey() // private key stays hidden until the user explicitly reveals it

      resultEl.classList.add('visible', 'found')
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      updateStats()

      stopRequested = true
    }
  }

  // Event listeners
  prefixInput.addEventListener('input', () => {
    prefixInput.value = sanitizeHex(prefixInput.value)
    updatePreview()
  })

  suffixInput.addEventListener('input', () => {
    suffixInput.value = sanitizeHex(suffixInput.value)
    updatePreview()
  })

  for (const input of searchTargetInputs) {
    input.addEventListener('change', () => {
      updatePreview()
    })
  }

  caseSensitive.addEventListener('change', () => {
    updatePreview()
  })

  btnGenerate.addEventListener('click', () => {
    if (runState.status === 'running') {
      stopRequested = true
    } else {
      run().catch((err) => {
        // Any unexpected failure (lost GPU device, shader compile error, worker
        // crash) must not strand the UI in a disabled 'running' state.
        console.error('[vanity] search failed', err)
        if (runState.status !== 'found') {
          subtitleEl.textContent = 'Something went wrong during the search — please reload the page.'
        }
        forceIdle()
      })
    }
  })

  // Enter key to start/stop
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && document.activeElement?.tagName !== 'BUTTON') {
      e.preventDefault()
      btnGenerate.click()
    }
  })

  const pkWarning = root.querySelector<HTMLDivElement>('#pk-warning')!
  let keyRevealed = false

  function maskKey() {
    keyRevealed = false
    pkText.textContent = '•'.repeat(64)
    copyPk.classList.add('hidden')
    pkWarning.classList.add('hidden')
    btnReveal.textContent = 'Reveal Key'
  }

  btnReveal.addEventListener('click', () => {
    if (!lastFound) return
    if (keyRevealed) { maskKey(); return }
    keyRevealed = true
    pkText.textContent = bytesToHex(lastFound.priv)
    copyPk.classList.remove('hidden')
    pkWarning.classList.remove('hidden')
    btnReveal.textContent = 'Hide Key'
  })

  // Re-mask a revealed key when the page loses focus / is hidden, so it isn't
  // left exposed over the shoulder or in a background tab.
  window.addEventListener('blur', () => { if (keyRevealed) maskKey() })
  document.addEventListener('visibilitychange', () => { if (document.hidden && keyRevealed) maskKey() })

  copyAddr.addEventListener('click', () => {
    if (lastFound) void copyToClipboard(lastFound.targetAddress, copyAddr)
  })

  copyWallet.addEventListener('click', () => {
    if (lastFound) void copyToClipboard(lastFound.walletAddress, copyWallet)
  })

  copyPk.addEventListener('click', () => {
    if (lastFound && pkText.textContent && !pkText.textContent.includes('\u2022')) {
      void copyToClipboard(pkText.textContent, copyPk)
    }
  })

  // Password modal — replaces a bare prompt() so a typo can't silently produce an
  // undecryptable keystore (which would be permanent fund loss).
  const pwModal = root.querySelector<HTMLDivElement>('#pw-modal')!
  const pwInput = root.querySelector<HTMLInputElement>('#pw-input')!
  const pwConfirm = root.querySelector<HTMLInputElement>('#pw-confirm')!
  const pwError = root.querySelector<HTMLDivElement>('#pw-error')!
  const pwOk = root.querySelector<HTMLButtonElement>('#pw-ok')!
  const pwCancel = root.querySelector<HTMLButtonElement>('#pw-cancel')!

  function promptPassword(): Promise<string | null> {
    return new Promise((resolve) => {
      pwInput.value = ''
      pwConfirm.value = ''
      pwError.textContent = ''
      pwModal.hidden = false
      pwInput.focus()

      const cleanup = () => {
        pwModal.hidden = true
        pwOk.removeEventListener('click', onOk)
        pwCancel.removeEventListener('click', onCancel)
        pwModal.removeEventListener('keydown', onKey)
        pwModal.removeEventListener('mousedown', onBackdrop)
      }
      const onOk = () => {
        const p = pwInput.value
        if (p.length < 8) { pwError.textContent = 'Password must be at least 8 characters.'; pwInput.focus(); return }
        if (p !== pwConfirm.value) { pwError.textContent = 'Passwords do not match.'; pwConfirm.focus(); return }
        cleanup(); resolve(p)
      }
      const onCancel = () => { cleanup(); resolve(null) }
      const onKey = (e: KeyboardEvent) => {
        if (e.key === 'Enter') { e.preventDefault(); onOk() }
        else if (e.key === 'Escape') { e.preventDefault(); onCancel() }
      }
      const onBackdrop = (e: MouseEvent) => { if (e.target === pwModal) onCancel() }

      pwOk.addEventListener('click', onOk)
      pwCancel.addEventListener('click', onCancel)
      pwModal.addEventListener('keydown', onKey)
      pwModal.addEventListener('mousedown', onBackdrop)
    })
  }

  btnDownload.addEventListener('click', async () => {
    if (!lastFound) return
    const password = await promptPassword()
    if (!password) return

    const prevText = btnDownload.textContent
    btnDownload.disabled = true
    btnDownload.textContent = 'Encrypting…'
    try {
      const ks: KeystoreV3 = await createKeystoreV3(lastFound.priv, password)
      const blob = new Blob([JSON.stringify(ks, null, 2)], { type: 'application/json' })
      const a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = `${lastFound.walletAddress}.json`
      a.click()
      URL.revokeObjectURL(a.href)
    } finally {
      btnDownload.disabled = false
      btnDownload.textContent = prevText
    }
  })

  const copyDonate = root.querySelector<HTMLButtonElement>('#copy-donate')!
  copyDonate.addEventListener('click', () => {
    void copyToClipboard('0x99999933F17A1339958d50b3f59740E5Ad48C74C', copyDonate)
  })

  // Initialize
  updatePreview()
}
