import fs from 'node:fs';
import path from 'node:path';
import Koa from 'koa';
import vm from 'node:vm';
import Config from '../config.mjs';
import TokenManager from './token.mjs';
import Storage from './storage.mjs';

const tm = new TokenManager(Config["token_key"])

/**
 * Token util for koa middleware
 * @param {Koa.Context} ctx
 */
function parseTokenData(ctx, checkExists = true) {
    const token = ctx.cookies.get('token');
    if (!token) return false;
    const data = tm.verify(token);
    if (!data) return false;
    if (checkExists && !Storage.account.has(data.uid)) return false;
    return data;
}


/**
 * @type {Koa.Middleware}
 */
export async function checkToken(ctx, next) {
    if (!parseTokenData(ctx)) {
        return ctx.throw(401);
    }
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function ensureAdmin(ctx, next) {
    const tokenData = parseTokenData(ctx);
    if (!tokenData || tokenData.role !== 'admin') {
        return ctx.throw(401);
    }
    ctx.token = tokenData;
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function ensureDeveloper(ctx, next) {
    const tokenData = parseTokenData(ctx);
    if (!tokenData || tokenData.role !== 'developer') {
        return ctx.throw(401);
    }
    ctx.token = tokenData;
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function ensureLocal(ctx, next) {
    if (ctx.request.ip !== '127.0.0.1' && ctx.request.ip !== '::1' && ctx.request.ip !== '::ffff:127.0.0.1') {
        return ctx.throw(403);
    }
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function cors(ctx, next) {
    ctx.set('Access-Control-Allow-Origin', 'null');
    ctx.set('Access-Control-Allow-Credentials', 'false');
    ctx.set('Access-Control-Allow-Headers', 'Content-Type');
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function csp(ctx, next) {
    const nonce = ctx.nonce ||
        crypto.randomBytes(18).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
    // let srcOriginPrefix = ctx.request.protocol + "://" + ctx.request.host.split(":")[0];
    let srcOriginPrefix = 'http://localhost';
    let assetsSrc = srcOriginPrefix + ':' + Config["assets_port"].toString();
    ctx.set('Content-Security-Policy', [
        ['default-src', `'self'`],
        ['script-src', `'nonce-${nonce}'`, 'blob:', assetsSrc],
        ['worker-src', `'self'`, 'blob:'],
        ['style-src', `'nonce-${nonce}'`, 'blob:'],
        ['connect-src', `'self'`, 'https:'],
        ['object-src', `'none'`],
        ['base-uri', `'self'`],
        ['frame-src', `'self'`, 'https://challenges.cloudflare.com']
    ].map(a => a.join(' ')).join(';'));
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function enableSAB(ctx, next) {
    ctx.set('Content-Type', 'text/html');
    ctx.set('Cross-Origin-Opener-Policy', 'same-origin');
    ctx.set('Cross-Origin-Embedder-Policy', 'require-corp');
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function template(ctx, next) {
    function renderContentWithArgs(content, data) {
        return content.replace(/{{ *([a-zA-Z$][a-zA-Z0-9_$]*) *}}/g, (_, key) => {
            if (Object.prototype.hasOwnProperty.call(data, key)) {
                if (typeof data[key] === 'undefined') return 'undefined';
                if (data[key] === null) return 'null';
                return data[key].toString();
            } else {
                return '';
            }
        });
    }

    ctx.render = async function (filepath, data) {
        try {
            let content = fs.readFileSync(path.resolve(filepath), 'utf-8');
            // handle {{ #loop <param> }}...{{ /loop }}
            content = content.replace(/{{ *#loop *([a-zA-Z$][a-zA-Z0-9_$]*) *}}([\s\S]*?){{ *\/loop *}}/g, (_, key, block) => {
                if (Object.prototype.hasOwnProperty.call(data, key)) {
                    let arr = data[key];
                    return arr.map(item => renderContentWithArgs(block, item)).join('');
                } else {
                    return '';
                }
            });
            // handle {{ #if <param> }}...{{ /if }}
            content = content.replace(/{{ *#if *([\s\S]*?) *}}([\s\S]*?){{ *\/if *}}/g, (_, condition, block) => {
                if (Boolean(vm.runInNewContext(condition, data))) {
                    return renderContentWithArgs(block, data);
                } else {
                    return '';
                }
            });
            // handle {{ <param> }}
            content = renderContentWithArgs(content, data);

            ctx.body = content;
            if (filepath.endsWith('.html')) {
                ctx.set('Content-Type', 'text/html');
            }
        } catch (e) {
            ctx.body = 'Internal Server Error';
            ctx.status = 500;
            console.error(ctx.request.url, e);
        }
    }
    await next();
}

/**
 * @type {Koa.Middleware}
 */
export async function receiveBodyComplete(ctx, next = async () => { }) {
    if (ctx.request.type === 'application/x-www-form-urlencoded') {
        let buf = await new Promise((resolve, reject) => {
            let chunks = [];
            ctx.req.on('data', chunk => chunks.push(chunk));
            ctx.req.on('end', () => resolve(Buffer.concat(chunks)));
            ctx.req.on('error', reject);
        });
        ctx.request.bodyBuffer = buf;
    }
    await next();
}

export const others = {
    tm, parseTokenData
}
