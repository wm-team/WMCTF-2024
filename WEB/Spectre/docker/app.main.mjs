import fs from 'node:fs';
import crypto from 'node:crypto';
import Koa from 'koa';;
import Router from 'koa-router';
import _static from 'koa-static';
import Config from './config.mjs'
import Storage from './src/storage.mjs';
import botRouter from './src/bot.mjs';
import { cors, csp, enableSAB, ensureAdmin, template, receiveBodyComplete } from './src/middleware.mjs';
import { others } from './src/middleware.mjs';
const { tm, parseTokenData } = others;

/* Router */

const root = new Router();

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/ /g, "&nbsp;");
}

root.get('/', cors, csp, enableSAB, (ctx, next) => { ctx.redirect('/list') });
root.get('/submit', cors, csp, enableSAB, async (ctx, next) => {
    const tokenData = parseTokenData(ctx);
    if (!tokenData) {
        // clear invalid token
        ctx.cookies.set('token', '', {
            httpOnly: true, sameSite: 'Strict', path: '/', domain: ctx.request.host.split(':')[0]
        });
        return ctx.redirect('/account/login' + `?next=${encodeURIComponent(ctx.request.path + ctx.request.search)}`);
    }
    await ctx.render('views/submit.html', {
        nonce: ctx.nonce,
        username: tokenData.uid,
        code: escapeHtml(Config["placeholder_code_default"])
    })
});

root.post('/submit', cors, async (ctx, next) => {
    // ensure content type
    if (ctx.request.type !== 'application/x-www-form-urlencoded') {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    // ensure login
    const tokenData = parseTokenData(ctx);
    if (!tokenData) {
        return ctx.body = { code: 401, message: "Unauthorized" }
    }
    // wait for body complete
    await receiveBodyComplete(ctx);
    // parse body
    let body = ctx.request.bodyBuffer.toString();
    let data = new URLSearchParams(body);
    let content = data.get('content') || '';
    let uuid = crypto.randomUUID();
    Storage.submission.set(uuid, {
        content,
        author: tokenData.uid,
        ts: Date.now()
    });
    ctx.body = { code: 200, message: "success", uuid }
})

root.get('/list', cors, csp, async (ctx, next) => {
    const tokenData = parseTokenData(ctx);
    if (!tokenData) {
        // clear invalid token
        ctx.cookies.set('token', '', {
            httpOnly: true, sameSite: 'Strict', path: '/', domain: ctx.request.host.split(':')[0]
        });
        return ctx.redirect('/account/login' + `?next=${encodeURIComponent(ctx.request.path + ctx.request.search)}`);
    }
    let submissions = [];
    for (let [uuid, submission] of Storage.submission) {
        if (submission.author === tokenData.uid || tokenData.role === 'developer' || tokenData.role === 'admin') {
            let time = new Date(submission.ts).toLocaleString();
            submissions.push({ uuid, time, author: submission.author, ts: submission.ts });
        }
    }
    submissions.sort((a, b) => b.ts - a.ts);
    if (tokenData.role === 'developer' || tokenData.role === 'admin') {
        await ctx.render('views/list.admin.html', {
            nonce: ctx.nonce,
            username: tokenData.uid,
            info: submissions
        });
    } else {
        await ctx.render('views/list.html', {
            nonce: ctx.nonce,
            username: tokenData.uid,
            info: submissions
        });
    }
})

root.get('/s/:uuid', cors, csp, enableSAB, async (ctx, next) => {
    const tokenData = parseTokenData(ctx);
    let uuid = ctx.params.uuid;

    function res_404() {
        ctx.render('views/share.404.html', {
            nonce: ctx.nonce,
            code: escapeHtml(Config["placeholder_code_404"])
        })
    }

    if (!Storage.submission.has(uuid) || !tokenData) return res_404();
    const submission = Storage.submission.get(uuid);
    if (submission.author !== tokenData.uid &&
        tokenData.role !== 'developer' &&
        tokenData.role !== 'admin') return res_404();

    ctx.set('Content-Type', 'text/html');
    if (tokenData.role === 'developer') {
        // if it's developer, serve the dev version
        await ctx.render('views/share.dev.html', {
            nonce: ctx.nonce,
            role: tokenData.role,
            script_src: '/assets/share-view.dev.js',
            code: submission.content,
            username: submission.author,
            uuid: uuid,
        })
    } else {
        // otherwise, serve the normal version
        await ctx.render('views/share.html', {
            nonce: ctx.nonce,
            role: tokenData.role,
            code: submission.content,
            username: submission.author,
            uuid: uuid
        })
    }
});

root.delete('/s/:uuid', cors, async (ctx, next) => {
    const tokenData = parseTokenData(ctx);
    let uuid = ctx.params.uuid;
    if (!Storage.submission.has(uuid) || !tokenData) {
        return ctx.body = { code: 404, message: "Not Found" }
    }
    const submission = Storage.submission.get(uuid);
    if (submission.author !== tokenData.uid && tokenData.role !== 'developer' && tokenData.role !== 'admin') {
        return ctx.body = { code: 404, message: "Not Found" }
    }
    Storage.submission.delete(uuid);
    return ctx.body = { code: 200, message: "success" }
})

root.get('/account/login', cors, csp, async (ctx, next) => {
    await ctx.render('views/login.html', {
        nonce: ctx.nonce
    })
})

root.get('/account/signup', cors, csp, async (ctx, next) => {
    await ctx.render('views/signup.html', {
        nonce: ctx.nonce
    })
})

root.post('/account/login', cors, async (ctx, next) => {
    // ensure content type
    if (ctx.request.type !== 'application/x-www-form-urlencoded') {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    // wait for body complete
    await receiveBodyComplete(ctx);
    // parse body
    let body = ctx.request.bodyBuffer.toString();
    let data = new URLSearchParams(body);
    let username = data.get('username');
    let password = data.get('password').toLowerCase();
    let remember = data.get('remember') === '1';
    if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    if (!/^[a-zA-Z0-9_]{3,10}$/.test(username) || !/^[a-f0-9]{64}$/.test(password)) {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    if (Storage.account.has(username)) {
        let account = Storage.account.get(username);
        if (account.password === password) {
            let token = tm.sign({ uid: username, role: account.role });
            // strict, expire in 7 days
            if (remember) {
                ctx.cookies.set('token', token, {
                    httpOnly: true, maxAge: 7 * 24 * 60 * 60 * 1000, sameSite: 'Strict', path: '/', domain: ctx.request.host.split(':')[0]
                });
            } else {
                ctx.cookies.set('token', token, {
                    httpOnly: true, sameSite: 'Strict', path: '/', domain: ctx.request.host.split(':')[0]
                });
            }
            return ctx.body = { code: 200, message: "success" }
        }
    }
    return ctx.body = { code: 401, message: "Unauthorized" }
})

root.post('/account/signup', cors, async (ctx, next) => {
    // ensure content type
    if (ctx.request.type !== 'application/x-www-form-urlencoded') {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    // wait for body complete
    await receiveBodyComplete(ctx);
    // parse body
    let body = ctx.request.bodyBuffer.toString();
    let data = new URLSearchParams(body);
    let username = data.get('username');
    let password = data.get('password');
    if (!username || !password) {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    if (!/^[a-zA-Z0-9_]{3,10}$/.test(username) || !/^[a-f0-9]{64}$/.test(password)) {
        return ctx.body = { code: 400, message: "Invalid request" }
    }
    if (Storage.account.has(username)) {
        return ctx.body = { code: 409, message: "Conflict" }
    }
    Storage.account.set(username, { password, role: Config["default_role"] });
    return ctx.body = { code: 200, message: "success" }
})

root.all('/account/logout', cors, csp, async (ctx, next) => {
    ctx.cookies.set('token', '', {
        httpOnly: true, sameSite: 'Strict', path: '/', domain: ctx.request.host.split(':')[0]
    });
    ctx.redirect('/account/login');
})

root.get('/flag', cors, csp, ensureAdmin, async (ctx, next) => {
    // let flag = fs.readFileSync('flag.txt');
    let flag = process.env?.FLAG || 'flag{test_flag}';
    ctx.body = `<pre><code>${flag}</code></pre>`
    ctx.set('Content-Type', 'text/html');
});

root.all('/assets/(.*)', (ctx, next) => {
    // let newHost = ctx.request.protocol + '://' + ctx.request.host.split(":")[0]
    let newOriginPrefix = 'http://localhost'
    let newOrigin = newOriginPrefix + ':' + Config["assets_port"].toString();
    let fullpath = ctx.request.path + ctx.request.search;
    let newPath = fullpath.replace(/^\/assets\//, '/')
    let uri = newOrigin + newPath;
    ctx.redirect(uri);
})

/* App */

const app = new Koa();

app.use(template);
app.use(async (ctx, next) => {
    ctx.storage = Storage;
    ctx.nonce = crypto.randomBytes(18).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
    await next();
})
app.use(root.routes()).use(root.allowedMethods());
app.use(botRouter.routes()).use(botRouter.allowedMethods());
app.use(_static('public'));

export default app;