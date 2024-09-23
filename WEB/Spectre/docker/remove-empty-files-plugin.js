const fs = require('fs');
const path = require('path');

class RemoveEmptyFilesPlugin {
    constructor(options) {
        this.options = options || {};
    }

    apply(compiler) {
        compiler.hooks.afterEmit.tapAsync('RemoveEmptyFilesPlugin', (compilation, callback) => {
            const outputPath = compilation.options.output.path;
            const assets = compilation.assets;

            Object.keys(assets).forEach((filename) => {
                const filePath = path.join(outputPath, filename);
                fs.stat(filePath, (err, stats) => {
                    if (err) {
                        console.error(`Error checking file ${filePath}:`, err);
                        return;
                    }
                    if (stats.size === 0) {
                        fs.unlink(filePath, (err) => {
                            if (err) {
                                console.error(`Error deleting empty file ${filePath}:`, err);
                            } else {
                                console.log(`Deleted empty file: ${filePath}`);
                            }
                        });
                    }
                });
            });

            callback();
        });
    }
}

module.exports = RemoveEmptyFilesPlugin;
