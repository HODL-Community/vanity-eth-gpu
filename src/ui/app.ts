import { bytesToHex, nowMs } from '../utils/hex'
import { createKeystoreV3, type KeystoreV3 } from '../wallet/keystoreV3'
import { type PrivKey32 } from '../wallet/keys'
import { createWorkerPool } from '../worker/pool'
import { createWasmWorkerPool, type WasmWorkerPool } from '../worker/wasmPool'
import { createGpuVanity } from '../webgpu/gpuVanity'
import { type SearchTarget, searchTargetToGpuMode } from '../searchTarget'
import { verifyFoundResult } from '../vanityResult'
import { ADDRESS_NIBBLE_LENGTH, calculatePatternDifficulty, mergeAddressPattern } from '../searchPattern'

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

function estimateTime(difficulty: number, speed: number): string {
  if (!Number.isFinite(difficulty)) return 'Impossible'
  if (speed === 0) return '-'
  const avgAttempts = difficulty / 2
  const seconds = avgAttempts / speed
  return '~' + formatTime(seconds)
}

function targetPreviewLabel(target: SearchTarget): string {
  return target === 'first-contract' ? 'First Contract Address Preview' : 'Wallet Address Preview'
}

function targetResultLabel(target: SearchTarget): string {
  return target === 'first-contract' ? 'First Contract Address' : 'Wallet Address'
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
          <input type="text" id="prefix" placeholder="c0ffee" spellcheck="false" autocomplete="off" maxlength="40" inputmode="text" pattern="[0-9a-fA-F]*">
        </div>
        <div class="field">
          <label for="suffix">Suffix</label>
          <input type="text" id="suffix" placeholder="beef" spellcheck="false" autocomplete="off" maxlength="40" inputmode="text" pattern="[0-9a-fA-F]*">
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
              <span>First Contract</span>
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

      <div class="helper-text" id="target-help">Wallet mode searches for an address controlled directly by the generated private key.</div>
      <div class="pattern-warning hidden" id="pattern-warning"></div>

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
        <div class="verification-proof" id="verification-proof"></div>
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
        </div>
        <div class="actions">
          <button class="btn" id="btn-reveal">Reveal Key</button>
          <button class="btn btn-primary" id="btn-download">Download Keystore</button>
        </div>
      </div>
    </div>

    <div class="footer">
      <div>All computations run locally in your browser. For maximum security, disconnect from the internet before generating.</div>
      <div class="built-by">Built by <a href="https://x.com/snapss" target="_blank" rel="noopener">@snapss</a> & <a href="https://claude.ai" target="_blank" rel="noopener">Claude</a></div>
      <div class="open-source"><a href="https://github.com/HODL-Community/vanity-eth-gpu" target="_blank" rel="noopener">Open Source</a> on GitHub</div>
      <div class="donate">Donate: <span class="donate-addr">0x99999933F17A1339958d50b3f59740E5Ad48C74C</span><button class="copy-btn-small" id="copy-donate">Copy</button></div>
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
  const targetHelp = root.querySelector<HTMLDivElement>('#target-help')!
  const patternWarning = root.querySelector<HTMLDivElement>('#pattern-warning')!
  const verificationProof = root.querySelector<HTMLDivElement>('#verification-proof')!

  // State
  let runState: RunState = { status: 'idle' }
  let stopRequested = false
  let lastFound: { priv: PrivKey32; targetAddress: string; walletAddress: string; target: SearchTarget } | null = null

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
    targetHelp.textContent = target === 'first-contract'
      ? 'First-contract mode targets the first CREATE address at nonce 0. Use the deployer before any other outgoing transaction.'
      : 'Wallet mode searches for an address controlled directly by the generated private key.'
  }

  function renderPreviewAddress(pattern: ReturnType<typeof mergeAddressPattern>) {
    previewAddr.replaceChildren(document.createTextNode('0x'))

    if (pattern.constrainedNibbles === 0 || !pattern.valid) {
      previewAddr.append(document.createTextNode(generateNoise(ADDRESS_NIBBLE_LENGTH, 0)))
      return
    }

    let noiseOffset = 0
    for (let i = 0; i < ADDRESS_NIBBLE_LENGTH; i++) {
      const known = pattern.body[i]
      if (known === null) {
        previewAddr.append(document.createTextNode(generateNoise(1, noiseOffset++)))
      } else {
        const span = document.createElement('span')
        span.className = 'match'
        span.textContent = known
        previewAddr.append(span)
      }
    }
  }

  // Update preview
  function updatePreview() {
    updateTargetLabels()
    const pre = sanitizeHex(prefixInput.value)
    const suf = sanitizeHex(suffixInput.value)
    const pattern = mergeAddressPattern(pre, suf, caseSensitive.checked)

    renderPreviewAddress(pattern)

    if (!pattern.valid) {
      patternWarning.textContent = pattern.message || 'This prefix/suffix request is impossible.'
      patternWarning.classList.remove('hidden')
    } else if (pre.length + suf.length === 0) {
      patternWarning.textContent = 'Enter a hex prefix or suffix to start.'
      patternWarning.classList.remove('hidden')
    } else {
      patternWarning.textContent = ''
      patternWarning.classList.add('hidden')
    }

    btnGenerate.disabled = runState.status !== 'running' && (!pattern.valid || pre.length + suf.length === 0)

    // Update ETA based on difficulty
    const difficulty = calculatePatternDifficulty(pre, suf, caseSensitive.checked)
    if (runState.status === 'running' && runState.speed > 0) {
      statEta.textContent = estimateTime(difficulty, runState.speed)
    } else if (!pattern.valid) {
      statEta.textContent = 'Impossible'
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
      const difficulty = calculatePatternDifficulty(pre, suf, caseSensitive.checked)
      statEta.textContent = estimateTime(difficulty, runState.speed)
    } else if (runState.status === 'found') {
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
    btnGenerate.textContent = 'Stop'
    btnGenerate.classList.add('running')
    previewEl.classList.add('generating')
    resultEl.classList.remove('visible', 'found')
    walletRow.classList.add('hidden')
    walletText.textContent = ''
    copyPk.classList.add('hidden')
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
    const pattern = mergeAddressPattern(pre, suf, caseSensitive.checked)

    if (!pattern.valid || pre.length + suf.length === 0) {
      resetUI()
      updatePreview()
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

    // ── Auto-benchmark on first run (GPU vs WASM vs CPU) ──
    if (cachedBackend === null) {
      const BENCH_DURATION_MS = 3000
      const BENCH_BATCH = 16384

      // Check if GPU is available at all
      let gpuAvailable = false
      try {
        const testGpu = await createGpuVanity()
        testGpu.destroy()
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
        // Benchmark GPU
        subtitleEl.textContent = 'Benchmarking GPU...'
        const dummyNibbles = [0, 0, 0, 0, 0, 0, 0, 0]
        let gpuChecked = 0
        const gpuVanity = await createGpuVanity()
        const gpuStart = nowMs()
        while (nowMs() - gpuStart < BENCH_DURATION_MS && !stopRequested) {
          await gpuVanity.search(dummyNibbles, dummyNibbles, BENCH_BATCH, searchTargetToGpuMode(target))
          gpuChecked += BENCH_BATCH
        }
        gpuSpeed = gpuChecked / ((nowMs() - gpuStart) / 1000)
        gpuVanity.destroy()

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
      if (gpuAvailable) parts.push(`GPU: ${formatNumber(Math.round(gpuSpeed))}/s`)
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
      // ── GPU path ──
      const gpuVanity = await createGpuVanity()
      subtitleEl.textContent = 'Running on GPU (WebGPU)'
      const prefixNibbles = hexToNibbles(preLower)
      const suffixNibbles = hexToNibbles(sufLower)
      const gpuBatchSize = 16384

      while (!stopRequested) {
        const result = await gpuVanity.search(
          prefixNibbles,
          suffixNibbles,
          gpuBatchSize,
          searchTargetToGpuMode(target)
        )

        if (result && runState.status === 'running') {
          const accepted = handleFound(result.privHex, result.addressHex, pre, suf, target)
          if (!accepted && runState.status === 'running') {
            cachedBackend = 'cpu'
            subtitleEl.textContent = 'GPU result failed validation, falling back to CPU...'
            break
          }
        }

        if (runState.status === 'running') {
          runState = { ...runState, generated: runState.generated + gpuBatchSize }
        }
        recentGenerated += gpuBatchSize

        const elapsed = nowMs() - recentStartMs
        if (elapsed >= 500 && runState.status === 'running') {
          const speed = Math.floor(recentGenerated / (elapsed / 1000))
          runState = { ...runState, speed }
          recentGenerated = 0
          recentStartMs = nowMs()
          updateStats()
        }
      }

      gpuVanity.destroy()
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
        subtitleEl.textContent = `Running on WASM (${pool.workerCount} workers)`
        const batchPerWorker = 16384

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
              handleFound(r.found.privHex, r.found.address, pre, suf, target)
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

        pool.destroy()
      }
    }

    // CPU fallback (also handles WASM→CPU fallback)
    if (cachedBackend === 'cpu' && !stopRequested && runState.status === 'running') {
      // ── CPU path ──
      const pool = createWorkerPool()
      subtitleEl.textContent = `Running on CPU (${pool.workerCount} workers)`
      const batchPerWorker = 16384

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
            handleFound(r.found.privHex, r.found.address, pre, suf, target)
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

      pool.destroy()
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

  function handleFound(privHex: string, foundAddress: string, pre: string, suf: string, target: SearchTarget): boolean {
    const verified = verifyFoundResult(privHex, foundAddress, pre, suf, target, caseSensitive.checked)

    if (verified) {
      const { priv, targetAddress: verifiedTargetAddress, walletAddress } = verified
      const timeS = (nowMs() - (runState as any).startedAtMs) / 1000
      const generated: number = runState.status === 'running' ? runState.generated : 0

      runState = { status: 'found', generated, time: timeS, foundPriv: priv, foundAddress: verifiedTargetAddress }
      lastFound = { priv, targetAddress: verifiedTargetAddress, walletAddress, target }
      resultAddrLabel.textContent = targetResultLabel(target)
      verificationProof.textContent = target === 'first-contract'
        ? 'Verified locally: this private key derives to the deployer wallet, and its first CREATE nonce-0 contract address matches this result.'
        : 'Verified locally: this private key derives to the displayed wallet address.'

      const preMatch = verifiedTargetAddress.slice(2, 2 + pre.length)
      const sufMatch = verifiedTargetAddress.slice(2 + 40 - suf.length)
      const midPart = verifiedTargetAddress.slice(2 + pre.length, 2 + 40 - suf.length)

      addrText.innerHTML = `0x<span class="highlight">${preMatch}</span>${midPart}<span class="highlight">${sufMatch}</span>`
      walletText.textContent = walletAddress
      if (target === 'first-contract') {
        walletRow.classList.remove('hidden')
      } else {
        walletRow.classList.add('hidden')
      }
      pkText.textContent = '\u2022'.repeat(64)

      resultEl.classList.add('visible', 'found')
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      updateStats()

      stopRequested = true
      return true
    }

    patternWarning.textContent = 'Rejected an invalid generated result before display. Retrying with a safer path.'
    patternWarning.classList.remove('hidden')

    return false
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
      void run()
    }
  })

  // Enter key to start/stop
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && document.activeElement?.tagName !== 'BUTTON') {
      e.preventDefault()
      btnGenerate.click()
    }
  })

  btnReveal.addEventListener('click', () => {
    if (lastFound) {
      pkText.textContent = bytesToHex(lastFound.priv)
      copyPk.classList.remove('hidden')
    }
  })

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

  btnDownload.addEventListener('click', async () => {
    if (!lastFound) return
    const password = prompt('Enter password for keystore encryption:')
    if (!password) return

    const ks: KeystoreV3 = await createKeystoreV3(lastFound.priv, password)
    const blob = new Blob([JSON.stringify(ks, null, 2)], { type: 'application/json' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `${lastFound.walletAddress}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  })

  const copyDonate = root.querySelector<HTMLButtonElement>('#copy-donate')!
  copyDonate.addEventListener('click', () => {
    void copyToClipboard('0x99999933F17A1339958d50b3f59740E5Ad48C74C', copyDonate)
  })

  // Initialize
  updatePreview()
}
