import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const rootDir = fileURLToPath(new URL('.', import.meta.url))

export default defineConfig({
  root: 'doc',
  build: {
    outDir: '../dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(rootDir, 'doc/index.html'),
        'docs-index': resolve(rootDir, 'doc/docs/index.html'),
        'docs-checks': resolve(rootDir, 'doc/docs/checks.html'),
        'docs-parameters': resolve(rootDir, 'doc/docs/parameters.html'),
        'zh-cn': resolve(rootDir, 'doc/zh-cn/index.html'),
        'zh-cn-docs-index': resolve(rootDir, 'doc/zh-cn/docs/index.html'),
        'zh-cn-docs-checks': resolve(rootDir, 'doc/zh-cn/docs/checks.html'),
        'zh-cn-docs-parameters': resolve(rootDir, 'doc/zh-cn/docs/parameters.html')
      }
    }
  }
})
