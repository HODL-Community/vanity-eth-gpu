import shaderSource from './base58Matcher.wgsl?raw'

const MAX_MATCH_LEN = 44
const MAX_BATCH_SIZE = 32768
const NO_MATCH = 0xffffffff
const PARAM_U32_COUNT = 4 + MAX_MATCH_LEN + MAX_MATCH_LEN

export type GpuMatcher = {
  findMatchIndex(
    pubKeys: Uint8Array,
    count: number,
    prefix: string,
    suffix: string,
    caseSensitive: boolean
  ): Promise<number | null>
  destroy(): void
}

export async function createGpuMatcher(): Promise<GpuMatcher> {
  if (!navigator.gpu) {
    throw new Error('WebGPU is not available')
  }

  const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' })
  if (!adapter) {
    throw new Error('No suitable WebGPU adapter found')
  }

  const device = await adapter.requestDevice()

  const module = device.createShaderModule({ code: shaderSource })
  const pipeline = device.createComputePipeline({
    layout: 'auto',
    compute: {
      module,
      entryPoint: 'main',
    },
  })

  const pubKeysBuffer = device.createBuffer({
    size: MAX_BATCH_SIZE * 32,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
  })

  const paramsBuffer = device.createBuffer({
    size: PARAM_U32_COUNT * 4,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
  })

  const resultBuffer = device.createBuffer({
    size: 4,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
  })

  const readbackBuffer = device.createBuffer({
    size: 4,
    usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ,
  })

  const bindGroup = device.createBindGroup({
    layout: pipeline.getBindGroupLayout(0),
    entries: [
      { binding: 0, resource: { buffer: pubKeysBuffer } },
      { binding: 1, resource: { buffer: paramsBuffer } },
      { binding: 2, resource: { buffer: resultBuffer } },
    ],
  })

  const paramsData = new Uint32Array(PARAM_U32_COUNT)
  let destroyed = false

  async function findMatchIndex(
    pubKeys: Uint8Array,
    count: number,
    prefix: string,
    suffix: string,
    caseSensitive: boolean
  ): Promise<number | null> {
    if (destroyed) throw new Error('GPU matcher was destroyed')
    if (count <= 0) return null
    if (count > MAX_BATCH_SIZE) {
      throw new Error(`Batch size ${count} exceeds MAX_BATCH_SIZE ${MAX_BATCH_SIZE}`)
    }

    const upload = pubKeys.slice(0, count * 32)
    device.queue.writeBuffer(pubKeysBuffer, 0, upload)

    paramsData.fill(0)
    paramsData[0] = count
    paramsData[1] = prefix.length
    paramsData[2] = suffix.length
    paramsData[3] = caseSensitive ? 1 : 0

    for (let i = 0; i < prefix.length; i++) {
      paramsData[4 + i] = prefix.charCodeAt(i)
    }

    for (let i = 0; i < suffix.length; i++) {
      paramsData[4 + MAX_MATCH_LEN + i] = suffix.charCodeAt(i)
    }

    device.queue.writeBuffer(paramsBuffer, 0, paramsData)
    device.queue.writeBuffer(resultBuffer, 0, new Uint32Array([NO_MATCH]))

    const encoder = device.createCommandEncoder()
    const pass = encoder.beginComputePass()
    pass.setPipeline(pipeline)
    pass.setBindGroup(0, bindGroup)
    pass.dispatchWorkgroups(Math.ceil(count / 256))
    pass.end()

    encoder.copyBufferToBuffer(resultBuffer, 0, readbackBuffer, 0, 4)
    device.queue.submit([encoder.finish()])

    await readbackBuffer.mapAsync(GPUMapMode.READ)
    const matchIndex = new Uint32Array(readbackBuffer.getMappedRange().slice(0))[0]
    readbackBuffer.unmap()

    if (matchIndex === NO_MATCH) return null
    return Number(matchIndex)
  }

  function destroy() {
    destroyed = true
    pubKeysBuffer.destroy()
    paramsBuffer.destroy()
    resultBuffer.destroy()
    readbackBuffer.destroy()
    device.destroy()
  }

  return { findMatchIndex, destroy }
}
