import shaderSource from './keccakMatch.wgsl?raw'

export type MatchRequest = {
  // Concatenated 64-byte pubkeys (x||y), length = batchSize*64
  pubkeys64: Uint8Array
  // hex nibbles (0..15)
  prefix: number[]
  suffix: number[]
}

type WebGpuMatcher = {
  match(req: MatchRequest): Promise<number[]>
  destroy(): void
}

const MAX_MATCHES = 1024

function u32Bytes(n: number) {
  return new Uint8Array(new Uint32Array([n >>> 0]).buffer)
}

function packParams(prefix: number[], suffix: number[]): Uint32Array {
  const out = new Uint32Array(4 + 40 + 40)
  out[0] = prefix.length
  out[1] = suffix.length
  // out[2], out[3] padding
  for (let i = 0; i < Math.min(40, prefix.length); i++) out[4 + i] = prefix[i] >>> 0
  for (let i = 0; i < Math.min(40, suffix.length); i++) out[4 + 40 + i] = suffix[i] >>> 0
  return out
}

export async function createWebGpuMatcher(): Promise<WebGpuMatcher> {
  if (!('gpu' in navigator)) throw new Error('WebGPU not supported')
  const adapter = await navigator.gpu.requestAdapter()
  if (!adapter) throw new Error('No WebGPU adapter')
  const device = await adapter.requestDevice()

  const module = device.createShaderModule({ code: shaderSource })
  const pipeline = device.createComputePipeline({
    layout: 'auto',
    compute: { module, entryPoint: 'main' },
  })

  // Buffers: we recreate pubkey buffer per batch size (since size varies), but reuse params+matches buffers.
  const paramsBuf = device.createBuffer({
    size: (4 + 40 + 40) * 4,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
  })

  const matchesBufSize = 4 + 4 * MAX_MATCHES
  const matchesBuf = device.createBuffer({
    size: matchesBufSize,
    usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
  })

  const readback = device.createBuffer({
    size: matchesBufSize,
    usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ,
  })

  let destroyed = false

  async function match(req: MatchRequest): Promise<number[]> {
    if (destroyed) throw new Error('matcher destroyed')
    const batchSize = Math.floor(req.pubkeys64.length / 64)
    if (batchSize <= 0 || batchSize * 64 !== req.pubkeys64.length) throw new Error('pubkeys64 length must be multiple of 64')
    if (batchSize > 16384) throw new Error('batch too large')
    if (req.prefix.length > 40 || req.suffix.length > 40) throw new Error('prefix/suffix too long (max 40 nibbles each)')

    // Pack pubkeys (Uint8Array) into u32[] (little-endian). In practice browsers are little-endian.
    const pubU32 = new Uint32Array(req.pubkeys64.buffer, req.pubkeys64.byteOffset, req.pubkeys64.byteLength / 4)

    const pubBuf = device.createBuffer({
      size: pubU32.byteLength,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    })

    device.queue.writeBuffer(pubBuf, 0, pubU32 as Uint32Array<ArrayBuffer>)
    device.queue.writeBuffer(paramsBuf, 0, packParams(req.prefix, req.suffix) as Uint32Array<ArrayBuffer>)
    device.queue.writeBuffer(matchesBuf, 0, u32Bytes(0)) // zero counter

    const bindGroup = device.createBindGroup({
      layout: pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: pubBuf } },
        { binding: 1, resource: { buffer: paramsBuf } },
        { binding: 2, resource: { buffer: matchesBuf } },
      ],
    })

    const encoder = device.createCommandEncoder()
    const pass = encoder.beginComputePass()
    pass.setPipeline(pipeline)
    pass.setBindGroup(0, bindGroup)
    const wgSize = 64
    const workgroups = Math.ceil(batchSize / wgSize)
    pass.dispatchWorkgroups(workgroups)
    pass.end()
    encoder.copyBufferToBuffer(matchesBuf, 0, readback, 0, matchesBufSize)
    device.queue.submit([encoder.finish()])

    await readback.mapAsync(GPUMapMode.READ)
    const bytes = new Uint8Array(readback.getMappedRange())
    const u32 = new Uint32Array(bytes.buffer, bytes.byteOffset, bytes.byteLength / 4)
    const count = Math.min(u32[0], MAX_MATCHES)
    const out: number[] = []
    for (let i = 0; i < count; i++) out.push(u32[1 + i])
    readback.unmap()

    pubBuf.destroy()
    return out
  }

  function destroy() {
    destroyed = true
    paramsBuf.destroy()
    matchesBuf.destroy()
    readback.destroy()
    device.destroy()
  }

  return { match, destroy }
}



