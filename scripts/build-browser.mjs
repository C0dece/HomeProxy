import { build } from 'esbuild'
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises'

const from = new URL('../apps/browser-extension/', import.meta.url)
const output = new URL('../dist/browser/', import.meta.url)
await mkdir(output, { recursive: true })
await build({
  entryPoints: ['background', 'popup'].map(name => new URL(name + '.ts', from).pathname.replace(/^\/(?=[A-Za-z]:)/, '')),
  outdir: output.pathname.replace(/^\/(?=[A-Za-z]:)/, ''),
  bundle: true,
  format: 'esm',
  target: 'chrome124'
})
await Promise.all(['popup.html', 'popup.css'].map(name => copyFile(new URL(name, from), new URL(name, output))))
const manifest = JSON.parse(await readFile(new URL('manifest.json', from), 'utf8'))
if (process.env.HOMEPROXY_RELEASE_VERSION) manifest.version = process.env.HOMEPROXY_RELEASE_VERSION
if (process.env.HOMEPROXY_BROWSER_UPDATE_URL) manifest.update_url = process.env.HOMEPROXY_BROWSER_UPDATE_URL
await writeFile(new URL('manifest.json', output), JSON.stringify(manifest, null, 2) + '\n')
await copyFile(new URL('../packages/ui/theme.css', import.meta.url), new URL('theme.css', output))
await copyFile(new URL('../apps/client/src-tauri/icons/icon.png', import.meta.url), new URL('icon.png', output))
