declare module 'picomatch' {
  interface PicomatchOptions {
    dot?: boolean
  }
  type PicomatchFn = (path: string) => boolean
  function picomatch(glob: string, options?: PicomatchOptions): PicomatchFn
  export default picomatch
}