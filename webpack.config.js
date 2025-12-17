const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');
const TerserPlugin = require('terser-webpack-plugin');

module.exports = (env, argv) => {
  const isProduction = argv.mode === 'production';

  return {
    entry: {
      // Main extension scripts - these need all dependencies bundled inline
      background: './src/background/index.js',
      content: './src/content/index.js',

      // UI pages
      'popup/popup': './src/popup/index.js',
      'settings/settings': './src/settings/index.js',
      'history/history': './src/history/index.js',

      // Injected scripts (main world) - self-contained
      'injected/network-interceptor': './src/injection/network-interceptor.js',
      'injected/framework-hooks': './src/injection/framework-hooks.js',
      'injected/dom-analyzer': './src/injection/dom-analyzer.js',

      // Web workers - self-contained
      'workers/scanner-worker': './src/workers/scanner-worker.js',
      'workers/payload-worker': './src/workers/payload-worker.js'
    },
    output: {
      path: path.resolve(__dirname, 'dist'),
      filename: '[name].js',
      clean: true
    },
    module: {
      rules: [
        {
          test: /\.js$/,
          exclude: /node_modules/,
          use: {
            loader: 'babel-loader',
            options: {
              presets: ['@babel/preset-env']
            }
          }
        }
      ]
    },
    optimization: {
      minimize: isProduction,
      minimizer: [
        new TerserPlugin({
          terserOptions: {
            compress: {
              drop_console: false, // Keep console.log for debugging
              drop_debugger: isProduction
            },
            format: {
              comments: false
            }
          },
          extractComments: false
        })
      ],
      // Disable code splitting - content scripts and workers need to be self-contained
      splitChunks: false
    },
    plugins: [
      new CopyPlugin({
        patterns: [
          { from: 'manifest.json', to: 'manifest.json' },
          { from: 'icons', to: 'icons' },
          { from: 'popup.css', to: 'popup.css' },
          { from: 'src/popup/popup.html', to: 'popup/popup.html' },
          { from: 'src/popup/popup.css', to: 'popup/popup.css' },
          { from: 'src/settings/settings.html', to: 'settings/settings.html' },
          { from: 'src/history/history.html', to: 'history/history.html' }
        ]
      })
    ],
    resolve: {
      extensions: ['.js'],
      alias: {
        '@shared': path.resolve(__dirname, 'src/shared'),
        '@detection': path.resolve(__dirname, 'src/detection'),
        '@scanners': path.resolve(__dirname, 'src/scanners'),
        '@exploits': path.resolve(__dirname, 'src/exploits'),
        '@safety': path.resolve(__dirname, 'src/safety'),
        '@integrations': path.resolve(__dirname, 'src/integrations')
      }
    },
    devtool: isProduction ? false : 'source-map',
    stats: {
      colors: true,
      modules: false,
      children: false,
      chunks: false,
      chunkModules: false
    }
  };
};
