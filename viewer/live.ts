import { useEffect, useState } from 'react'

let liveProbe: Promise<boolean> | null = null

export function useLive(): boolean {
  const [live, setLive] = useState(false)
  useEffect(() => {
    liveProbe ??= fetch('live').then((r) => r.ok).catch(() => false)
    liveProbe.then(setLive)
  }, [])
  return live
}