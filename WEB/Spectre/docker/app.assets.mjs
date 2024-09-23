import Koa from 'koa';
import _static from 'koa-static';
import Config from './config.mjs';
import { cors, ensureLocal, template } from './src/middleware.mjs'
import { others } from './src/middleware.mjs'
const { tm } = others;

function isDeveloper(ctx, next) {
    const token = ctx.request.headers.cookie['token'];
    if (!token) { return false; }
    const data = tm.verify(token);
    if (!data || data.role !== 'developer') { return false; }
    return true;
}

const app = new Koa();

// app.use(cors);
app.use(async (ctx, next) => {
    ctx.set('Access-Control-Allow-Origin', '*');
    await next();
})
app.use(ensureLocal);
// app.use(ensureDeveloper);
app.use(template);
app.use(async (ctx, next) => {
    if (ctx.path === '/share-view.dev.js') {
        // if (!isDeveloper(ctx)) { return ctx.throw(403); }
        let array_string = "[" + Config["token_key"].split('').map(e => e.charCodeAt(0)).join(',') + ']';
        const rnd_string = (n = 0) => [...Array(n)].map(() => (~~(Math.random() * 36)).toString(36)).join('');
        await ctx.render('assets/share-view.dev.js', {
            token_key: array_string,
            func_name: '_' + rnd_string(17),
            wrapper_name: '_' + rnd_string(16),
        });
        ctx.set('Content-Type', 'application/javascript');
    } else {
        await next();
    }
})
app.use(_static('assets'));

export default app;