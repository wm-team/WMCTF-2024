import Config from './config.mjs';
import MainApp from './app.main.mjs';
import AssetsApp from './app.assets.mjs';

MainApp.listen(Config["main_port"], () => {
    console.log(`[Main] serve on http://localhost:${Config["main_port"]}`);
})

AssetsApp.listen(Config["assets_port"], () => {
    console.log(`[Assets] serve on http://localhost:${Config["assets_port"]}`);
})