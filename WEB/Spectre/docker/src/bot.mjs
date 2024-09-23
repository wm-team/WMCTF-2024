import Router from 'koa-router';
import crypto from 'node:crypto';
import puppeteer from 'puppeteer';
import { PassThrough } from 'node:stream';
import Config from '../config.mjs';
import { cors, csp } from './middleware.mjs';
import Storage from './storage.mjs';
import { others } from './middleware.mjs';
const { tm, parseTokenData } = others;

const router = new Router();

const prefix = "http://localhost:3000/s/";

function setTimer(timeout, interval, options) {
    if (typeof options !== 'object') options = {};
    const _start = options.start;
    const _end = options.end;
    const _moment = options.moment;
    return new Promise((resolve, reject) => {
        let startTime = Date.now();
        if (typeof _start === 'function') _start(startTime, 0).catch(e => console.error(e));
        let itvid = setInterval(async () => {
            let now = Date.now();
            if (typeof _moment === 'function') _moment(now, now - startTime).catch(e => console.error(e));
        }, interval);
        setTimeout(async () => {
            clearInterval(itvid);
            let now = Date.now();
            if (typeof _end === 'function') _end(now, now - startTime).catch(e => console.error(e));
            resolve();
        }, timeout);
    })
}

function randomString(alphabet, length) {
    return Array.from({ length: length }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join('');
}

function createRandomUser(role, overflow = 0) {
    // never conflict on client side if overflow > 0
    const alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
    let uid = randomString(alphabet, 10 + overflow);
    let password = randomString(alphabet, 20 + overflow);
    let password_sha256 = crypto.createHash('sha256').update(password).digest('hex');
    Storage.account.set(uid, { password: password_sha256, role: role });
    return { uid, password, password_sha256, role };
}

function genDefaultAccount() {
    console.log("------ Default Account ------");
    let d = createRandomUser('developer');
    console.log(`Developer uid: ${d.uid}`);
    console.log(`Developer password: ${d.password}`);
    console.log(`Developer password sha256: ${d.password_sha256}`);
    let a = createRandomUser('admin');
    console.log(`Admin uid: ${a.uid}`);
    console.log(`Admin password: ${a.password}`);
    console.log(`Admin password sha256: ${a.password_sha256}`);
    console.log("-----------------------------");
}

if (Config["generate_default_account"]) {
    genDefaultAccount();
}

router.get('/bot', cors, csp, async (ctx, next) => {
    // SSE
    const headerAccepts = ctx.headers['accept'].split(',').map(e => e.trim());
    function acceptContains(type) {
        return headerAccepts.some(e => e.split(';')[0].trim() === type)
    }
    if (acceptContains('text/event-stream')) {
        ctx.set('Content-Type', 'text/event-stream');
        ctx.set('Cache-Control', 'no-cache');
        ctx.set('Connection', 'keep-alive');
        const stream = new PassThrough();
        ctx.body = stream;
        ctx.req.on('close', () => { stream.end(); });
        handleSSE(ctx, next, stream);
        return;
    }
    // HTML
    const tokenData = parseTokenData(ctx);
    if (!tokenData) {
        // clear invalid token
        ctx.cookies.set('token', '', {
            httpOnly: true, sameSite: 'Strict', path: '/', domain: ctx.request.host.split(':')[0]
        });
        return ctx.redirect('/account/login' + `?next=${encodeURIComponent(ctx.request.path + ctx.request.search)}`);
    }
    await ctx.render('views/bot.html', {
        nonce: ctx.nonce,
        username: tokenData.uid,
        prefix: prefix,
        site_key: Config["cf_turnstile"]["site_key"],
        captcha: Config["cf_turnstile"]["enable"]
    })
})

async function verifyCFTurnstile(response) {
    try {
        const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({ response: response, secret: Config["cf_turnstile"]["secret_key"] }).toString()
        });
        const data = await resp.json();
        if (data.success) return true;
    } catch (e) { return false; }
    return false;
}

/**
 * @param {import('koa').Context} ctx
 * @param {import('koa').Next} next
 * @param {import('stream').Writable} stream
 */
async function handleSSE(ctx, next, _stream) {
    const stream = _stream;
    function sendData(data) {
        let data_string = JSON.stringify(data);
        let sent_data = data_string.split('\n').map(e => `data: ${e}`).join('\n');
        stream.write(`${sent_data}\n\n`);
    }
    function sendEvt(event, data) {
        let data_string = JSON.stringify(data);
        let sent_data = data_string.split('\n').map(e => `data: ${e}`).join('\n');
        stream.write(`event: ${event}\n${sent_data}\n\n`);
    }

    // verify token
    const tokenData = parseTokenData(ctx);
    if (!tokenData) {
        return sendEvt("res:error", { code: 401, message: 'Unauthorized' });
    }
    // verify input
    const url = Buffer.from(ctx.headers["x-bot-visit"] || '', 'base64').toString();
    if (!url || !url.startsWith(prefix) || /[^a-zA-Z0-9\-]/.test(url.slice(prefix.length))) {
        return sendEvt("res:error", { code: 400, message: 'Invalid request' });
    }
    // verify turnstile
    if (Config["cf_turnstile"]["enable"]) {
        const cf_response = Buffer.from(ctx.headers["cf-turnstile-response"] || '', 'base64').toString();
        if (!cf_response || !(await verifyCFTurnstile(cf_response))) {
            return sendEvt("res:error", { code: 403, message: 'Forbidden' });
        }
    }

    // create temp user data
    let userdata = createRandomUser('developer', 1);

    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--disable-gpu',
            "--no-sandbox",
            '--disable-dev-shm-usage'
        ]
    });

    let meet_error = false;
    const page = await browser.newPage();
    try {

        await page.setCookie({
            name: 'token',
            value: tm.sign({
                uid: userdata.uid,
                role: userdata.role
            }),
            httpOnly: true,
            path: '/',
            domain: 'localhost',
            sameSite: 'Strict'
        });
        await page.goto(url, { timeout: 3 * 1000 });

        await setTimer(Config["bot_visit_timeout"], 1000, {
            start: async (startTime) => {
                let pageTitle = await page.title().catch(e => "");
                sendData({ code: 201, message: 'Start', data: { delta: 0, title: pageTitle, start_time: startTime } });
            },
            end: async (_, delta) => {
                let pageTitle = await page.title().catch(e => "");
                sendData({ code: 200, message: 'Done', data: { delta: delta, title: pageTitle } });
            },
            moment: async (_, delta) => {
                let pageTitle = await page.title().catch(e => "");
                sendData({ code: 202, message: 'Processing', data: { delta: delta, title: pageTitle } });
            }
        }).catch(e => console.error(e));

        await page.close();
    } catch (e) {
        meet_error = true;
        console.error(e);
        await page.close().catch(e => void 0);
    }

    try {
        await browser.close();
    } catch (e) {
        meet_error = true;
        console.error(e);
    }

    // clean temp user data
    Storage.account.delete(userdata.uid);
    for (let [uuid, submission] of Storage.submission) {
        if (submission.author === userdata.uid) {
            Storage.submission.delete(uuid);
        }
    }

    if (meet_error) {
        sendEvt("res:error", { code: 500, message: 'Internal Server Error' });
    } else {
        sendEvt("res:done", { code: 200, message: 'Success' });
    }
    stream.end();
}

export default router;