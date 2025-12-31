import VanityWorker from './vanityWorker?worker'

type SearchResult = {
  checked: number
  found: { privHex: string; address: string } | null
}

type PendingTask = {
  resolve: (result: SearchResult) => void
}

export type WorkerPool = {
  search(prefixLower: string, suffixLower: string, batchSize: number): Promise<SearchResult>
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
    worker.onmessage = (e) => {
      const { id, checked, found } = e.data
      const task = pending.get(id)
      if (task) {
        pending.delete(id)
        task.resolve({ checked, found })
      }
    }
    workers.push(worker)
  }

  let workerIndex = 0

  function search(prefixLower: string, suffixLower: string, batchSize: number): Promise<SearchResult> {
    if (destroyed) return Promise.reject(new Error('Pool destroyed'))

    return new Promise((resolve) => {
      const id = nextId++
      pending.set(id, { resolve })

      const worker = workers[workerIndex]
      workerIndex = (workerIndex + 1) % workerCount

      worker.postMessage({
        type: 'search',
        id,
        batchSize,
        prefixLower,
        suffixLower
      })
    })
  }

  function destroy() {
    destroyed = true
    workers.forEach(w => w.terminate())
    workers.length = 0
    pending.clear()
  }

  return { search, destroy, workerCount }
}
