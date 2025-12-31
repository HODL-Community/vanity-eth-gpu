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
    // Little-endian u32 to bytes
    hex += (val & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 8) & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 16) & 0xff).toString(16).padStart(2, '0')
    hex += ((val >> 24) & 0xff).toString(16).padStart(2, '0')
  }
  return hex
}

export async function createGpuVanity(): Promise<GpuVanity> {
  if (!navigator.gpu) throw new Error('WebGPU not supported')

  const adapter = await navigator.gpu.requestAdapter()
  if (!adapter) throw new Error('No WebGPU adapter')

  const device = await adapter.requestDevice()

  const module = device.createShaderModule({ code: shaderSource })

  const pipeline = device.createComputePipeline({
    layout: 'auto',
    compute: { module, entryPoint: 'main' }
  })

  // Params buffer: [batchSize, prefixLen, suffixLen, reserved, prefix[40], suffix[40]]
  const paramsBuffer = device.createBuffer({
    size: (4 + 40 + 40) * 4,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST
  })

  // Results buffer: [count, results...]
  // Each result: 8 u32 priv + 8 u32 hash + 1 idx = 17 u32s
  // Max 16 results = 1 + 16*17 = 273 u32s
  const resultsSize = 274 * 4
  const resultsBuffer = device.createBuffer({
    size: resultsSize,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST
  })

  const readbackBuffer = device.createBuffer({
    size: resultsSize,
    usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ
  })

  let destroyed = false

  async function search(
    prefixNibbles: number[],
    suffixNibbles: number[],
    batchSize: number
  ): Promise<GpuVanityResult | null> {
    if (destroyed) throw new Error('GPU vanity destroyed')

    // Generate random seeds on CPU
    const seedData = new Uint32Array(batchSize * 8)
    crypto.getRandomValues(seedData)

    const seedBuffer = device.createBuffer({
      size: seedData.byteLength,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST
    })
    device.queue.writeBuffer(seedBuffer, 0, seedData)

    // Pack params
    const params = new Uint32Array(4 + 40 + 40)
    params[0] = batchSize
    params[1] = prefixNibbles.length
    params[2] = suffixNibbles.length
    params[3] = 0 // reserved
    for (let i = 0; i < prefixNibbles.length; i++) {
      params[4 + i] = prefixNibbles[i]
    }
    for (let i = 0; i < suffixNibbles.length; i++) {
      params[44 + i] = suffixNibbles[i]
    }
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
    pass.dispatchWorkgroups(Math.ceil(batchSize / 64))
    pass.end()

    encoder.copyBufferToBuffer(resultsBuffer, 0, readbackBuffer, 0, resultsSize)
    device.queue.submit([encoder.finish()])

    await readbackBuffer.mapAsync(GPUMapMode.READ)
    const resultData = new Uint32Array(readbackBuffer.getMappedRange().slice(0))
    readbackBuffer.unmap()

    seedBuffer.destroy()

    const count = resultData[0]
    if (count > 0) {
      // Extract first result
      const base = 1
      const privHex = u32ArrayToHex(resultData, base, 8)

      // Extract address from hash (last 20 bytes = bytes 12-31)
      // Hash is in resultData[base+8..base+15]
      const hashHex = u32ArrayToHex(resultData, base + 8, 8)
      // Address is last 40 hex chars of the 64-char hash
      const addressHex = hashHex.slice(24)

      return { privHex, addressHex }
    }

    return null
  }

  function destroy() {
    destroyed = true
    paramsBuffer.destroy()
    resultsBuffer.destroy()
    readbackBuffer.destroy()
    device.destroy()
  }

  return { search, destroy }
}
