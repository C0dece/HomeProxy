// Offline ISO/IEC 18004 QR Code (Error Correction Level M, versions 1..20) SVG generator.

type EccSpec = readonly [ecPerBlock: number, g1Blocks: number, g1Data: number, g2Blocks: number, g2Data: number]

// Capacity table for Error Correction Level M (format bits indicator 00), versions 1..20.
const ECC_M: readonly EccSpec[] = [
  [10, 1, 16, 0, 0],
  [16, 1, 28, 0, 0],
  [26, 1, 44, 0, 0],
  [18, 2, 32, 0, 0],
  [24, 2, 43, 0, 0],
  [16, 4, 27, 0, 0],
  [18, 4, 31, 0, 0],
  [22, 2, 38, 2, 39],
  [22, 3, 36, 2, 37],
  [26, 4, 43, 1, 44],
  [30, 1, 50, 4, 51],
  [22, 6, 36, 2, 37],
  [22, 8, 37, 1, 38],
  [24, 4, 40, 5, 41],
  [24, 5, 41, 5, 42],
  [28, 7, 45, 3, 46],
  [28, 10, 46, 1, 47],
  [26, 9, 43, 4, 44],
  [26, 3, 44, 11, 45],
  [26, 3, 41, 13, 42]
]

function gfMul(a: number, b: number): number {
  let x = a
  let y = b
  let z = 0
  for (let i = 0; i < 8; i++) {
    if (y & 1) z ^= x
    const hi = x & 0x80
    x = (x << 1) & 0xff
    if (hi) x ^= 0x1d
    y >>= 1
  }
  return z
}

function rsDivisor(degree: number): Uint8Array {
  const result = new Uint8Array(degree)
  result[degree - 1] = 1
  let root = 1
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = gfMul(result[j], root)
      if (j + 1 < degree) result[j] ^= result[j + 1]
    }
    root = gfMul(root, 2)
  }
  return result
}

function rsRemainder(data: Uint8Array, divisor: Uint8Array): Uint8Array {
  const result = new Uint8Array(divisor.length)
  for (const b of data) {
    const factor = b ^ result[0]
    result.copyWithin(0, 1)
    result[result.length - 1] = 0
    for (let i = 0; i < divisor.length; i++) {
      result[i] ^= gfMul(divisor[i], factor)
    }
  }
  return result
}

function alignmentPositions(version: number): number[] {
  if (version === 1) return []
  const count = Math.floor(version / 7) + 2
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2
  const pos = [6]
  for (let i = count - 1, val = version * 4 + 10; i >= 1; i--, val -= step) {
    pos.splice(1, 0, val)
  }
  return pos
}

function encodeData(bytes: Uint8Array): { version: number; codewords: Uint8Array } {
  for (let i = 0; i < ECC_M.length; i++) {
    const version = i + 1
    const [ecLen, g1Blocks, g1Data, g2Blocks, g2Data] = ECC_M[i]
    const totalData = g1Blocks * g1Data + g2Blocks * g2Data
    const charCountBits = version < 10 ? 8 : 16
    const bitLen = 4 + charCountBits + bytes.length * 8
    if (bitLen > totalData * 8) continue

    const buf = new Uint8Array(totalData)
    let bitPos = 0
    const pushBits = (val: number, len: number) => {
      for (let b = len - 1; b >= 0; b--) {
        if ((val >>> b) & 1) buf[bitPos >> 3] |= 0x80 >>> (bitPos & 7)
        bitPos++
      }
    }

    pushBits(0b0100, 4) // Byte mode
    pushBits(bytes.length, charCountBits)
    for (const byte of bytes) pushBits(byte, 8)
    // Terminator (up to 4 zero bits) and byte alignment are naturally 0-initialized.
    let padStart = Math.ceil(Math.min(bitPos + 4, totalData * 8) / 8)
    for (let p = 0; padStart + p < totalData; p++) {
      buf[padStart + p] = p % 2 === 0 ? 0xec : 0x11
    }

    // Split into blocks, compute Reed-Solomon ECC, and interleave.
    const divisor = rsDivisor(ecLen)
    const blocks: { data: Uint8Array; ecc: Uint8Array }[] = []
    let offset = 0
    for (let b = 0; b < g1Blocks + g2Blocks; b++) {
      const len = b < g1Blocks ? g1Data : g2Data
      const slice = buf.subarray(offset, offset + len)
      offset += len
      blocks.push({ data: slice, ecc: rsRemainder(slice, divisor) })
    }

    const maxData = g2Blocks > 0 ? g2Data : g1Data
    const out = new Uint8Array(totalData + (g1Blocks + g2Blocks) * ecLen)
    let k = 0
    for (let j = 0; j < maxData; j++) {
      for (const blk of blocks) {
        if (j < blk.data.length) out[k++] = blk.data[j]
      }
    }
    for (let j = 0; j < ecLen; j++) {
      for (const blk of blocks) out[k++] = blk.ecc[j]
    }
    return { version, codewords: out }
  }
  throw new Error('QR payload exceeds supported length')
}

function drawFunctionPatterns(version: number): { size: number; modules: Uint8Array; isFunc: Uint8Array } {
  const size = version * 4 + 17
  const modules = new Uint8Array(size * size)
  const isFunc = new Uint8Array(size * size)
  const setFunc = (x: number, y: number, dark: boolean) => {
    if (x < 0 || y < 0 || x >= size || y >= size) return
    modules[y * size + x] = dark ? 1 : 0
    isFunc[y * size + x] = 1
  }

  const drawFinder = (cx: number, cy: number) => {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const dist = Math.max(Math.abs(dx), Math.abs(dy))
        setFunc(cx + dx, cy + dy, dist !== 2 && dist !== 4)
      }
    }
  }
  drawFinder(3, 3)
  drawFinder(size - 4, 3)
  drawFinder(3, size - 4)

  for (let i = 8; i < size - 8; i++) {
    setFunc(i, 6, i % 2 === 0)
    setFunc(6, i, i % 2 === 0)
  }

  const align = alignmentPositions(version)
  for (let i = 0; i < align.length; i++) {
    for (let j = 0; j < align.length; j++) {
      if ((i === 0 && j === 0) || (i === 0 && j === align.length - 1) || (i === align.length - 1 && j === 0)) continue
      const cx = align[i]
      const cy = align[j]
      for (let dy = -2; dy <= 2; dy++) {
        for (let dx = -2; dx <= 2; dx++) {
          setFunc(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1)
        }
      }
    }
  }

  // Reserve format info (drawn per mask) and dark module.
  for (let i = 0; i <= 8; i++) {
    if (i !== 6) {
      setFunc(8, i, false)
      setFunc(i, 8, false)
    }
    if (i < 8) {
      setFunc(size - 1 - i, 8, false)
      setFunc(8, size - 1 - i, false)
    }
  }
  setFunc(8, size - 8, true)

  if (version >= 7) {
    let rem = version
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25)
    const bits = (version << 12) | rem
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0
      const a = size - 11 + (i % 3)
      const b = Math.floor(i / 3)
      setFunc(a, b, dark)
      setFunc(b, a, dark)
    }
  }

  return { size, modules, isFunc }
}

function drawFormatBits(modules: Uint8Array, size: number, mask: number) {
  // Format level M = 0 -> data = (0 << 3) | mask = mask
  const data = mask & 7
  let rem = data
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537)
  const bits = ((data << 10) | rem) ^ 0x5412

  for (let i = 0; i <= 5; i++) modules[i * size + 8] = (bits >>> i) & 1
  modules[7 * size + 8] = (bits >>> 6) & 1
  modules[8 * size + 8] = (bits >>> 7) & 1
  modules[8 * size + 7] = (bits >>> 8) & 1
  for (let i = 9; i < 15; i++) modules[8 * size + (14 - i)] = (bits >>> i) & 1

  for (let i = 0; i < 8; i++) modules[8 * size + (size - 1 - i)] = (bits >>> i) & 1
  for (let i = 8; i < 15; i++) modules[(size - 15 + i) * size + 8] = (bits >>> i) & 1
  modules[(size - 8) * size + 8] = 1
}

function maskBit(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0
    case 1: return y % 2 === 0
    case 2: return x % 3 === 0
    case 3: return (x + y) % 3 === 0
    case 4: return (Math.floor(y / 2) + Math.floor(x / 3)) % 2 === 0
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0
    default: return (((x + y) % 2) + ((x * y) % 3)) % 2 === 0
  }
}

function penaltyScore(modules: Uint8Array, size: number): number {
  let score = 0
  const at = (x: number, y: number) => modules[y * size + x]

  // N1: adjacent same-color modules in rows and columns.
  for (let y = 0; y < size; y++) {
    let runColor = at(0, y)
    let runLen = 1
    for (let x = 1; x < size; x++) {
      const c = at(x, y)
      if (c === runColor) {
        runLen++
      } else {
        if (runLen >= 5) score += 3 + (runLen - 5)
        runColor = c
        runLen = 1
      }
    }
    if (runLen >= 5) score += 3 + (runLen - 5)
  }
  for (let x = 0; x < size; x++) {
    let runColor = at(x, 0)
    let runLen = 1
    for (let y = 1; y < size; y++) {
      const c = at(x, y)
      if (c === runColor) {
        runLen++
      } else {
        if (runLen >= 5) score += 3 + (runLen - 5)
        runColor = c
        runLen = 1
      }
    }
    if (runLen >= 5) score += 3 + (runLen - 5)
  }

  // N2: 2x2 blocks.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const c = at(x, y)
      if (c === at(x + 1, y) && c === at(x, y + 1) && c === at(x + 1, y + 1)) score += 3
    }
  }

  // N3: finder-like 1:1:3:1:1 patterns.
  const matchFinder = (line: (i: number) => number) => {
    for (let i = 0; i <= size - 11; i++) {
      const p =
        line(i) === 1 && line(i + 1) === 0 && line(i + 2) === 1 && line(i + 3) === 1 &&
        line(i + 4) === 1 && line(i + 5) === 0 && line(i + 6) === 1
      if (!p) continue
      const leftLight = line(i + 7) === 0 && line(i + 8) === 0 && line(i + 9) === 0 && line(i + 10) === 0
      const rightLight = i + 10 < size && line(i) === 0 && line(i + 1) === 0 && line(i + 2) === 0 && line(i + 3) === 0 &&
        line(i + 4) === 1 && line(i + 5) === 0 && line(i + 6) === 1 && line(i + 7) === 1 &&
        line(i + 8) === 1 && line(i + 9) === 0 && line(i + 10) === 1
      if (leftLight || rightLight) score += 40
    }
  }
  for (let y = 0; y < size; y++) matchFinder(x => at(x, y))
  for (let x = 0; x < size; x++) matchFinder(y => at(x, y))

  // N4: dark ratio balance.
  let dark = 0
  for (const m of modules) dark += m
  const k = Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size))
  score += k * 10

  return score
}

export function qrMatrix(text: string): { size: number; modules: Uint8Array } {
  const bytes = new TextEncoder().encode(text)
  const { version, codewords } = encodeData(bytes)
  const { size, modules: base, isFunc } = drawFunctionPatterns(version)

  // Place codewords in upward/downward 2-column zig-zag.
  let bitIdx = 0
  const totalBits = codewords.length * 8
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5
    for (let vert = 0; vert < size; vert++) {
      for (let j = 0; j < 2; j++) {
        const x = right - j
        const upward = ((right + 1) & 2) === 0
        const y = upward ? size - 1 - vert : vert
        if (!isFunc[y * size + x] && bitIdx < totalBits) {
          const dark = ((codewords[bitIdx >> 3] >>> (7 - (bitIdx & 7))) & 1) !== 0
          base[y * size + x] = dark ? 1 : 0
          bitIdx++
        }
      }
    }
  }

  let bestMask = 0
  let bestScore = Infinity
  let bestModules = new Uint8Array(base.length)
  const candidate = new Uint8Array(base.length)

  for (let mask = 0; mask < 8; mask++) {
    candidate.set(base)
    for (let y = 0; y < size; y++) {
      for (let x = 0; x < size; x++) {
        const idx = y * size + x
        if (!isFunc[idx] && maskBit(mask, x, y)) candidate[idx] ^= 1
      }
    }
    drawFormatBits(candidate, size, mask)
    const s = penaltyScore(candidate, size)
    if (s < bestScore) {
      bestScore = s
      bestMask = mask
      bestModules.set(candidate)
    }
  }

  void bestMask
  return { size, modules: bestModules }
}

export function qrToSvg(text: string, margin = 3): string {
  const { size, modules } = qrMatrix(text)
  const total = size + margin * 2
  const parts: string[] = []
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (modules[y * size + x]) {
        parts.push(`M${x + margin},${y + margin}h1v1h-1z`)
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" role="img" aria-label="QR-код для sing-box iOS" shape-rendering="crispEdges"><rect width="${total}" height="${total}" rx="2" fill="#ffffff"/><path d="${parts.join('')}" fill="#09090b"/></svg>`
}
