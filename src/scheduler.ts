export function parseMaxConcurrency(
  raw: string,
  defaultValue: number,
  maximum: number,
): number {
  const value = raw.trim();
  if (value === "") return defaultValue;
  if (!/^\d+$/.test(value)) {
    throw new Error(`max-concurrency must be an integer between 1 and ${maximum}`);
  }

  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
    throw new Error(`max-concurrency must be an integer between 1 and ${maximum}`);
  }
  return parsed;
}

export async function mapConcurrent<T, R>(
  items: readonly T[],
  maxConcurrency: number,
  task: (item: T) => Promise<R>,
): Promise<R[]> {
  if (!Number.isInteger(maxConcurrency) || maxConcurrency < 1) {
    throw new Error("maxConcurrency must be a positive integer");
  }
  if (items.length === 0) return [];

  const results = new Array<R>(items.length);
  let nextIndex = 0;

  async function worker(): Promise<void> {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await task(items[index]);
    }
  }

  const workerCount = Math.min(maxConcurrency, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

export async function mapConcurrentWithBarriers<T, R>(
  items: readonly T[],
  maxConcurrency: number,
  isBarrier: (item: T) => boolean,
  task: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  let batch: T[] = [];

  async function flushBatch(): Promise<void> {
    if (batch.length === 0) return;
    results.push(...(await mapConcurrent(batch, maxConcurrency, task)));
    batch = [];
  }

  for (const item of items) {
    if (!isBarrier(item)) {
      batch.push(item);
      continue;
    }

    await flushBatch();
    results.push(await task(item));
  }

  await flushBatch();
  return results;
}
