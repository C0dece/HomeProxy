import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto'
import { readFile, writeFile } from 'node:fs/promises'

const [archive, privateKeyFile, output, updateXml, version, download] = process.argv.slice(2)
if (!download || !/^\d+\.\d+\.\d+$/.test(version)) {
  throw new Error('Usage: pack-browser.mjs zip private-key crx update.xml version https-download-url')
}
const parsed = new URL(download)
if (parsed.protocol !== 'https:' || parsed.username || parsed.password) throw new Error('An HTTPS download URL is required')

function varint(value) {
  const bytes = []
  while (value >= 128) {
    bytes.push((value & 127) | 128)
    value >>>= 7
  }
  return Buffer.from([...bytes, value])
}

function field(tag, bytes) {
  return Buffer.concat([varint(tag * 8 + 2), varint(bytes.length), bytes])
}

function uint32(value) {
  const bytes = Buffer.alloc(4)
  bytes.writeUInt32LE(value)
  return bytes
}

const key = createPrivateKey(await readFile(privateKeyFile))
if (key.asymmetricKeyType !== 'rsa') throw new Error('The extension signing key must be RSA')
const publicKey = createPublicKey(key).export({ type: 'spki', format: 'der' })
const id = createHash('sha256').update(publicKey).digest().subarray(0, 16)
const extensionId = [...id.toString('hex')].map(digit => String.fromCharCode(97 + parseInt(digit, 16))).join('')
const zip = await readFile(archive)
const signedHeader = field(1, id)
const signature = sign('sha256', Buffer.concat([
  Buffer.from('CRX3 SignedData\0'), uint32(signedHeader.length), signedHeader, zip,
]), key)
const header = Buffer.concat([field(2, Buffer.concat([field(1, publicKey), field(2, signature)])), field(10000, signedHeader)])
await writeFile(output, Buffer.concat([Buffer.from('Cr24'), uint32(3), uint32(header.length), header, zip]))
const escaped = parsed.href.replaceAll('&', '&amp;').replaceAll('"', '&quot;')
await writeFile(updateXml, `<?xml version="1.0" encoding="UTF-8"?>\n<gupdate xmlns="http://www.google.com/update2/response" protocol="2.0">\n  <app appid="${extensionId}"><updatecheck codebase="${escaped}" version="${version}" /></app>\n</gupdate>\n`)
console.log(extensionId)
