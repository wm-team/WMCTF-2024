import path from 'node:path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import ElementPlus from 'unplugin-element-plus/vite'
import Components from 'unplugin-vue-components/vite'
import Icons from 'unplugin-icons/vite'
import IconsResolver from 'unplugin-icons/resolver'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

// https://vitejs.dev/config/
export default defineConfig({
  server: {
    port: 3143,
    proxy: {
      '/api': {
        target: 'http://localhost:3031',
        changeOrigin: true,
      }
    }
  },
  base: '/',
  publicDir: 'public',
  build: {
    assetsDir: 'assets',
    outDir: 'dist',
    rollupOptions: {
      output: {
        entryFileNames: 'assets/[name].[hash].js',
        chunkFileNames: 'assets/[name].[hash].js',
        assetFileNames: 'assets/[name].[hash].[ext]',
      },
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  plugins: [
    vue(),
    // automatically import to reduce the size of the bundle
    AutoImport({
      resolvers: [
        ElementPlusResolver({ importStyle: 'sass' }),
        IconsResolver({
          prefix: 'Icon',
        })
      ],
    }),
    // auto import style
    ElementPlus({
      format: 'esm',
    }),
    // element-plus components
    Components({
      resolvers: [ElementPlusResolver()],
    }),
    // element-plus icons
    Icons({
      autoInstall: true,
    }),
  ],
})
