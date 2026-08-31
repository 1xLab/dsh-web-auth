import { defineConfig } from 'tsdown'

const PLUGIN_ID = 'dsh-web-auth'

export default defineConfig([
  {
    name: PLUGIN_ID,
    entry: { index: 'src/index.ts' },
    outDir: 'lib',
    format: 'esm',
    platform: 'node',
    target: 'es2024',
    fixedExtension: false,
    dts: false,
    clean: true,
  },
])
