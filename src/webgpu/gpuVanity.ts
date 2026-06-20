import shaderSource from './secp256k1.wgsl?raw'

export type GpuVanityResult = {
  privHex: string
  addressHex: string
}

export type GpuVanity = {
  label: string
  search(prefixNibbles: number[], suffixNibbles: number[], batchSize: number, searchMode: number): Promise<GpuVanityResult | null>
  destroy(): void
}

export type GpuVanityPool = {
  // One independent instance per physical GPU.
  instances: GpuVanity[]
  // Human-readable label per instance, same order as `instances`.
  labels: string[]
  destroy(): void
}

// Little-endian u32 array to hex (for hash output)
function u32ArrayToHexLE(arr: Uint32Array, start: number, count: number): string {
  let hex = ''
  for (let i = 0; i < count; i++) {
    const val = arr[start + i]
    hex += (val & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 8) & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 16) & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 24) & 0xff).toString(16).padStart(2, '0')
  }
  return hex
}

// Little-endian limbs to big-endian hex (for private key)
function u32ArrayToHexBE(arr: Uint32Array, start: number, count: number): string {
  let hex = ''
  // Reverse limb order and byte order
  for (let i = count - 1; i >= 0; i--) {
    const val = arr[start + i]
    hex += ((val >> 24) & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 16) & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 8) & 0xff).toString(16).padStart(2, '0')
    hex += (val & 0xff).toString(16).padStart(2, '0')
  }
  return hex
}

const MAX_BATCH_SIZE = 32768

// Build a short, human-readable label from a GPUAdapter's info.
function adapterLabel(adapter: GPUAdapter, index: number): string {
  // `info` is the modern synchronous accessor; older browsers exposed
  // `requestAdapterInfo()` instead. Either way we degrade gracefully.
  const info = (adapter as { info?: GPUAdapterInfo }).info
  if (info) {
    const name = info.description || [info.vendor, info.architecture].filter(Boolean).join(' ')
    if (name) return name
  }
  return `GPU ${index + 1}`
}

// Stable identity key so we don't run two devices on the same physical GPU.
function adapterKey(adapter: GPUAdapter, index: number): string {
  const info = (adapter as { info?: GPUAdapterInfo }).info
  if (info) {
    const key = [info.vendor, info.architecture, info.device, info.description]
      .filter(Boolean)
      .join('|')
    if (key) return key
  }
  return `adapter-${index}`
}

// Discover the distinct physical GPUs the browser is willing to expose.
// WebGPU has no "enumerate all adapters" API — the only lever is
// powerPreference, which on multi-GPU machines surfaces different chips.
export async function enumerateGpuAdapters(): Promise<GPUAdapter[]> {
  if (!navigator.gpu) throw new Error('WebGPU not supported')

  const prefs: GPUPowerPreference[] = ['high-performance', 'low-power']
  const adapters: GPUAdapter[] = []
  const seen = new Set<string>()

  for (const powerPreference of prefs) {
    let adapter: GPUAdapter | null = null
    try {
      adapter = await navigator.gpu.requestAdapter({ powerPreference })
    } catch {
      adapter = null
    }
    if (!adapter) continue
    const key = adapterKey(adapter, adapters.length)
    if (seen.has(key)) continue
    seen.add(key)
    adapters.push(adapter)
  }

  // Fallback: a default request if powerPreference yielded nothing.
  if (adapters.length === 0) {
    const adapter = await navigator.gpu.requestAdapter()
    if (adapter) adapters.push(adapter)
  }

  return adapters
}

export async function createGpuVanity(adapter?: GPUAdapter, label?: string): Promise<GpuVanity> {
  if (!navigator.gpu) throw new Error('WebGPU not supported')

  const resolvedAdapter = adapter ?? await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' })
  if (!resolvedAdapter) throw new Error('No WebGPU adapter')
  const resolvedLabel = label ?? adapterLabel(resolvedAdapter, 0)

  const device = await resolvedAdapter.requestDevice()

  // Surface device-loss for diagnostics. An in-flight search will reject when the
  // device is lost, which the caller's error handler turns into UI recovery.
  let destroyed = false
  void device.lost.then((info) => {
    if (!destroyed) console.warn(`[vanity] WebGPU device "${resolvedLabel}" lost: ${info.reason ?? 'unknown'} — ${info.message}`)
  })

  const module = device.createShaderModule({ code: shaderSource })

  const pipeline = device.createComputePipeline({
    layout: 'auto',
    compute: { module, entryPoint: 'main' }
  })

  // Params buffer
  const paramsBuffer = device.createBuffer({
    size: (4 + 40 + 40) * 4,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST
  })

  // Pre-allocate seed buffer for max batch size
  const seedBuffer = device.createBuffer({
    size: MAX_BATCH_SIZE * 8 * 4,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST
  })

  // Results buffer
  const resultsSize = 274 * 4
  const resultsBuffer = device.createBuffer({
    size: resultsSize,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST
  })

  // Double-buffered readback
  const readbackBuffers = [
    device.createBuffer({ size: resultsSize, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ }),
    device.createBuffer({ size: resultsSize, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ })
  ]
  let currentReadback = 0
  let pendingMap: Promise<void> | null = null

  // Pre-allocate seed data array
  const seedData = new Uint32Array(MAX_BATCH_SIZE * 8)

  // Reusable params array
  const params = new Uint32Array(4 + 40 + 40)

  async function search(
    prefixNibbles: number[],
    suffixNibbles: number[],
    batchSize: number,
    searchMode: number
  ): Promise<GpuVanityResult | null> {
    if (destroyed) throw new Error('GPU vanity destroyed')
    if (batchSize > MAX_BATCH_SIZE) batchSize = MAX_BATCH_SIZE

    // Generate random seeds (chunked for 65536 byte limit)
    const seedView = seedData.subarray(0, batchSize * 8)
    const maxU32s = 65536 / 4
    for (let offset = 0; offset < seedView.length; offset += maxU32s) {
      const chunk = seedView.subarray(offset, Math.min(offset + maxU32s, seedView.length))
      crypto.getRandomValues(chunk)
    }
    device.queue.writeBuffer(seedBuffer, 0, seedView)

    // Pack params
    params[0] = batchSize
    params[1] = prefixNibbles.length
    params[2] = suffixNibbles.length
    params[3] = searchMode
    for (let i = 0; i < prefixNibbles.length; i++) params[4 + i] = prefixNibbles[i]
    for (let i = 0; i < suffixNibbles.length; i++) params[44 + i] = suffixNibbles[i]
    device.queue.writeBuffer(paramsBuffer, 0, params)

    // Clear results counter
    device.queue.writeBuffer(resultsBuffer, 0, new Uint32Array([0]))

    const bindGroup = device.createBindGroup({
      layout: pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: seedBuffer } },
        { binding: 1, resource: { buffer: paramsBuffer } },
        { binding: 2, resource: { buffer: resultsBuffer } }
      ]
    })

    const encoder = device.createCommandEncoder()
    const pass = encoder.beginComputePass()
    pass.setPipeline(pipeline)
    pass.setBindGroup(0, bindGroup)
    pass.dispatchWorkgroups(Math.ceil(batchSize / 256))
    pass.end()

    // Use double buffering
    const readbackBuffer = readbackBuffers[currentReadback]
    currentReadback = 1 - currentReadback

    // Wait for any pending map from previous iteration
    if (pendingMap) {
      await pendingMap
      pendingMap = null
    }

    encoder.copyBufferToBuffer(resultsBuffer, 0, readbackBuffer, 0, resultsSize)
    device.queue.submit([encoder.finish()])

    await readbackBuffer.mapAsync(GPUMapMode.READ)
    const resultData = new Uint32Array(readbackBuffer.getMappedRange().slice(0))
    readbackBuffer.unmap()

    const count = resultData[0]
    if (count > 0) {
      const base = 1
      const privHex = u32ArrayToHexBE(resultData, base, 8)  // Big-endian for wallet import
      const hashHex = u32ArrayToHexLE(resultData, base + 8, 8)
      const addressHex = hashHex.slice(24)
      return { privHex, addressHex }
    }

    return null
  }

  function destroy() {
    destroyed = true
    paramsBuffer.destroy()
    seedBuffer.destroy()
    resultsBuffer.destroy()
    readbackBuffers[0].destroy()
    readbackBuffers[1].destroy()
    device.destroy()
  }

  return { label: resolvedLabel, search, destroy }
}

// Create one independent GpuVanity instance per distinct physical GPU.
// Falls back to a single instance when only one GPU is available.
export async function createGpuVanityPool(): Promise<GpuVanityPool> {
  const adapters = await enumerateGpuAdapters()
  if (adapters.length === 0) throw new Error('No WebGPU adapter')

  const instances: GpuVanity[] = []
  const labels: string[] = []

  for (let i = 0; i < adapters.length; i++) {
    try {
      const inst = await createGpuVanity(adapters[i], adapterLabel(adapters[i], i))
      instances.push(inst)
      labels.push(inst.label)
    } catch {
      // Skip a GPU whose device creation failed; others may still work.
    }
  }

  if (instances.length === 0) throw new Error('Failed to create any GPU device')

  return {
    instances,
    labels,
    destroy() {
      for (const inst of instances) inst.destroy()
    },
  }
}
