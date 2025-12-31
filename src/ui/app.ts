import { bytesToHex, hexToBytes, nowMs } from '../utils/hex'
import { createKeystoreV3, type KeystoreV3 } from '../wallet/keystoreV3'
import { checksumAddress } from '../wallet/ethAddress'
import { type PrivKey32 } from '../wallet/keys'
import { createWorkerPool } from '../worker/pool'

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
  // Case-sensitive: each letter has ~50% chance to match case (EIP-55)
  const letters = countLetters(prefix) + countLetters(suffix)
  return base * Math.pow(2, letters)
}

function estimateTime(difficulty: number, speed: number): string {
  if (speed === 0) return '-'
  const avgAttempts = difficulty / 2
  const seconds = avgAttempts / speed
  return '~' + formatTime(seconds)
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
        <div class="preview-label">Address Preview</div>
        <div class="preview-address" id="preview-addr">0x0000000000000000000000000000000000000000</div>
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
        <label class="checkbox-wrap">
          <input type="checkbox" id="case-sensitive">
          <span>Case-sensitive (EIP-55)</span>
        </label>
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
          <div class="result-label">Address</div>
          <div class="result-value" id="result-addr">
            <span id="addr-text"></span>
            <button class="copy-btn" id="copy-addr">Copy</button>
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
      <div class="open-source"><a href="https://github.com/HODL-Community/vanity-eth-gpu" target="_blank" rel="noopener">Open Source</a> on GitHub</div>
      <div class="donate">Donate: <span class="donate-addr">0x99999933F17A1339958d50b3f59740E5Ad48C74C</span></div>
    </div>
  `

  // Elements
  const prefixInput = root.querySelector<HTMLInputElement>('#prefix')!
  const suffixInput = root.querySelector<HTMLInputElement>('#suffix')!
  const caseSensitive = root.querySelector<HTMLInputElement>('#case-sensitive')!
  const previewEl = root.querySelector<HTMLDivElement>('#preview')!
  const previewAddr = root.querySelector<HTMLDivElement>('#preview-addr')!
  const btnGenerate = root.querySelector<HTMLButtonElement>('#btn-generate')!
  const statSpeed = root.querySelector<HTMLDivElement>('#stat-speed')!
  const statChecked = root.querySelector<HTMLDivElement>('#stat-checked')!
  const statEta = root.querySelector<HTMLDivElement>('#stat-eta')!
  const resultEl = root.querySelector<HTMLDivElement>('#result')!
  const addrText = root.querySelector<HTMLSpanElement>('#addr-text')!
  const pkText = root.querySelector<HTMLSpanElement>('#pk-text')!
  const copyAddr = root.querySelector<HTMLButtonElement>('#copy-addr')!
  const copyPk = root.querySelector<HTMLButtonElement>('#copy-pk')!
  const btnReveal = root.querySelector<HTMLButtonElement>('#btn-reveal')!
  const btnDownload = root.querySelector<HTMLButtonElement>('#btn-download')!
  const subtitleEl = root.querySelector<HTMLDivElement>('#subtitle')!

  // State
  let runState: RunState = { status: 'idle' }
  let stopRequested = false
  let lastFound: { priv: PrivKey32; address: string } | null = null

  // Deterministic noise based on position (looks random but stable)
  const noiseChars = '7a3f8c2e9b1d5046'
  function generateNoise(len: number, offset: number): string {
    let result = ''
    for (let i = 0; i < len; i++) {
      result += noiseChars[(i + offset * 7) % noiseChars.length]
    }
    return result
  }

  // Update preview
  function updatePreview() {
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
    } else if (runState.status === 'found') {
      statChecked.textContent = formatNumber(runState.generated)
      statEta.textContent = `Found in ${formatTime(runState.time)}`
    }
  }

  // Main generation loop - GPU first, fallback to workers
  async function run() {
    stopRequested = false
    btnGenerate.textContent = 'Stop'
    btnGenerate.classList.add('running')
    previewEl.classList.add('generating')
    resultEl.classList.remove('visible', 'found')
    copyPk.classList.add('hidden')
    lastFound = null

    const pre = sanitizeHex(prefixInput.value)
    const suf = sanitizeHex(suffixInput.value)
    const preLower = pre.toLowerCase()
    const sufLower = suf.toLowerCase()

    if (pre.length + suf.length === 0) {
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      return
    }

    const startedAtMs = nowMs()
    runState = { status: 'running', startedAtMs, generated: 0, speed: 0 }

    let recentGenerated = 0
    let recentStartMs = nowMs()

    // CPU workers using @noble libraries
    const pool = createWorkerPool()
    subtitleEl.textContent = `Running on CPU (${pool.workerCount} workers)`
    const batchPerWorker = 16384

    while (!stopRequested) {
      const promises = []
      for (let i = 0; i < pool.workerCount; i++) {
        promises.push(pool.search(preLower, sufLower, batchPerWorker))
      }

      const results = await Promise.all(promises)
      let totalChecked = 0

      for (const r of results) {
        totalChecked += r.checked
        if (r.found && runState.status === 'running') {
          const foundAddress = checksumAddress(r.found.address)
          handleFound(r.found.privHex, foundAddress, pre, suf)
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

    if (!stopRequested || runState.status === 'running') {
      btnGenerate.textContent = 'Generate'
      btnGenerate.classList.remove('running')
      previewEl.classList.remove('generating')
      subtitleEl.textContent = 'Fast vanity address generator'
      runState = { status: 'idle' }
    }
  }

  function handleFound(privHex: string, foundAddress: string, pre: string, suf: string) {
    const preLower = pre.toLowerCase()
    const sufLower = suf.toLowerCase()
    const addrToCompare = caseSensitive.checked ? foundAddress : foundAddress.toLowerCase()

    const prefixOk = addrToCompare.slice(2).startsWith(preLower) ||
      (caseSensitive.checked && addrToCompare.slice(2).startsWith(pre))
    const suffixOk = addrToCompare.slice(2).endsWith(sufLower) ||
      (caseSensitive.checked && addrToCompare.slice(2).endsWith(suf))

    if (prefixOk && suffixOk) {
      const priv = hexToBytes(privHex) as PrivKey32
      const timeS = (nowMs() - (runState as any).startedAtMs) / 1000
      const generated: number = runState.status === 'running' ? runState.generated : 0

      runState = { status: 'found', generated, time: timeS, foundPriv: priv, foundAddress }
      lastFound = { priv, address: foundAddress }

      const preMatch = foundAddress.slice(2, 2 + pre.length)
      const sufMatch = foundAddress.slice(2 + 40 - suf.length)
      const midPart = foundAddress.slice(2 + pre.length, 2 + 40 - suf.length)

      addrText.innerHTML = `0x<span class="highlight">${preMatch}</span>${midPart}<span class="highlight">${sufMatch}</span>`
      pkText.textContent = '\u2022'.repeat(64)

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

  btnReveal.addEventListener('click', () => {
    if (lastFound) {
      pkText.textContent = bytesToHex(lastFound.priv)
      copyPk.classList.remove('hidden')
    }
  })

  copyAddr.addEventListener('click', () => {
    if (lastFound) void copyToClipboard(lastFound.address, copyAddr)
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
    a.download = `${lastFound.address}.json`
    a.click()
    URL.revokeObjectURL(a.href)
  })

  // Initialize
  updatePreview()
}
