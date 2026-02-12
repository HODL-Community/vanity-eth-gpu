import VanityWorker from './vanityWorker?worker'
import type { SearchTarget } from '../searchTarget'

type SearchResult = {
  checked: number
  found: { privHex: string; address: string } | null
}

type GeneratedBatch = {
  checked: number
  privKeys: Uint8Array
  pubKeys: Uint8Array
}

type PendingTask =
  | { kind: 'search'; resolve: (result: SearchResult) => void }
  | { kind: 'generate'; resolve: (result: GeneratedBatch) => void }

type WorkerMessage =
  | { type: 'result'; id: number; checked: number; found: { privHex: string; address: string } | null }
  | { type: 'batch'; id: number; checked: number; privKeys: Uint8Array; pubKeys: Uint8Array }

export type WorkerPool = {
  search(
    prefix: string,
    suffix: string,
    batchSize: number,
    target: SearchTarget,
    caseSensitive: boolean
  ): Promise<SearchResult>
  generate(batchSize: number): Promise<GeneratedBatch>
  destroy(): void
  workerCount: number
}

export function createWorkerPool(): WorkerPool {
  const workerCount = Math.max(1, navigator.hardwareConcurrency || 4)
  const workers: Worker[] = []
  const pending = new Map<number, PendingTask>()
  let nextId = 0
  let destroyed = false

  for (let i = 0; i < workerCount; i++) {
    const worker = new VanityWorker()
    worker.onmessage = (e: MessageEvent<WorkerMessage>) => {
      const message = e.data
      const task = pending.get(message.id)
      if (!task) return

      pending.delete(message.id)

      if (message.type === 'result' && task.kind === 'search') {
        task.resolve({ checked: message.checked, found: message.found })
        return
      }

      if (message.type === 'batch' && task.kind === 'generate') {
        task.resolve({
          checked: message.checked,
          privKeys: message.privKeys,
          pubKeys: message.pubKeys,
        })
      }
    }
    workers.push(worker)
  }

  let workerIndex = 0

  function nextWorker(): Worker {
    const worker = workers[workerIndex]
    workerIndex = (workerIndex + 1) % workerCount
    return worker
  }

  function search(
    prefix: string,
    suffix: string,
    batchSize: number,
    target: SearchTarget,
    caseSensitive: boolean
  ): Promise<SearchResult> {
    if (destroyed) return Promise.reject(new Error('Pool destroyed'))

    return new Promise((resolve) => {
      const id = nextId++
      pending.set(id, { kind: 'search', resolve })

      nextWorker().postMessage({
        type: 'search',
        id,
        batchSize,
        prefix,
        suffix,
        caseSensitive,
        target,
      })
    })
  }

  function generate(batchSize: number): Promise<GeneratedBatch> {
    if (destroyed) return Promise.reject(new Error('Pool destroyed'))

    return new Promise((resolve) => {
      const id = nextId++
      pending.set(id, { kind: 'generate', resolve })

      nextWorker().postMessage({
        type: 'generate',
        id,
        batchSize,
      })
    })
  }

  function destroy() {
    destroyed = true
    workers.forEach(w => w.terminate())
    workers.length = 0
    pending.clear()
  }

  return { search, generate, destroy, workerCount }
}
