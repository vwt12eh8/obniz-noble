const path = require('path');
const nodeExternals = require('webpack-node-externals');

module.exports = {
  mode: 'development',
  entry: './index.js',
  output: {
    filename: 'obniz-noble.js',
    path: path.join(__dirname),

    library: 'obnizNoble',
  },
  devtool: 'none',
  module: {
    rules: [
      {
        test: /\.(css)$/,
        use: 'raw-loader',
      },
      {
        test: /\.(yml|yaml)$/,
        use: [
          {
            loader: require.resolve('json-loader'),
          },
          {
            // loader: require.resolve('yaml-loader')
            loader: require.resolve(
                './node_modules/obniz/dist/src/obniz/libs/webpackReplace/yaml-schema-loader'
            ),
          },
        ],
      },
    ],
  },
  externals: [
    nodeExternals({
      modulesFromFile: {
        include: ['devDependencies'],
      },
    }),
  ],
  stats: {
    warningsFilter: [
      /(?!require function is used in a way in which dependencies cannot be statically extracted)/,
    ],
  },
};
