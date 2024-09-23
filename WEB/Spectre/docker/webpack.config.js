const path = require('path');
const { CleanWebpackPlugin } = require('clean-webpack-plugin');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const TerserPlugin = require('terser-webpack-plugin');
const CssMinimizerPlugin = require('css-minimizer-webpack-plugin');
const RemoveEmptyFilesPlugin = require('./remove-empty-files-plugin');

module.exports = (env, argv) => {
    const mode = argv.mode || 'development';

    return {
        mode: mode,
        devtool: (mode === "development") ? 'source-map' : false,
        watch: (mode === "development"),
        entry: {
            account: './public-src/javascripts/account.mjs',
            'code-view': './public-src/javascripts/code-view.mjs',
            bot: './public-src/javascripts/bot.mjs'
        },
        output: {
            filename: '[name].bundle.js',
            path: path.resolve(__dirname, 'public/dist'),
        },
        module: {
            rules: [
                {
                    test: /\.js$/,
                    exclude: /node_modules/,
                    use: {
                        loader: 'babel-loader',
                        options: {
                            presets: ['@babel/preset-env'],
                        },
                    },
                },
                {
                    test: /\.css$/,
                    use: [MiniCssExtractPlugin.loader, 'css-loader'],
                },
                {
                    test: /\.scss$/,
                    use: [
                        MiniCssExtractPlugin.loader,
                        'css-loader',
                        'sass-loader',
                    ],
                },
            ],
        },
        optimization: {
            minimize: true,
            minimizer: [
                new TerserPlugin({
                    test: /\.js(\?.*)?$/i,
                }),
                new CssMinimizerPlugin({
                    test: /\.(c|sc|sa)ss(\?.*)?$/i,
                }),
            ],
        },
        plugins: [
            new MiniCssExtractPlugin({
                filename: '[name].bundle.css',
            }),
            new CleanWebpackPlugin({
                cleanOnceBeforeBuildPatterns: [
                    '**/*',
                    // path.resolve(__dirname, 'public/dist')
                ],
                cleanStaleWebpackAssets: false,
                protectWebpackAssets: false,
            }),
            new RemoveEmptyFilesPlugin(),
        ],
    }
}