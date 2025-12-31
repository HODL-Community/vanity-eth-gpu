import shaderSource from './secp256k1.wgsl?raw'

export type GpuVanityResult = {
  privHex: string
  addressHex: string
}

export type GpuVanity = {
  search(prefixNibbles: number[], suffixNibbles: number[], batchSize: number): Promise<GpuVanityResult | null>
  destroy(): void
}

function u32ArrayToHex(arr: Uint32Array, start: number, count: number): string {
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

const MAX_BATCH_SIZE = 32768

export async function createGpuVanity(): Promise<GpuVanity> {
  if (!navigator.gpu) throw new Error('WebGPU not supported')

  const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' })
  if (!adapter) throw new Error('No WebGPU adapter')

  const device = await adapter.requestDevice()

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

  let destroyed = false

  async function search(
    prefixNibbles: number[],
    suffixNibbles: number[],
    batchSize: number
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
    params[3] = 0
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
      const privHex = u32ArrayToHex(resultData, base, 8)
      const hashHex = u32ArrayToHex(resultData, base + 8, 8)
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

  return { search, destroy }
}
