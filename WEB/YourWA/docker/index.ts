import { runCode, handleUnArchive, runEntry, getProblemInfo, handleDelUploadedArchive, supportExtensions } from "./src/run"
import { Res, fitpath, restPath, isContentType, parseBody, resolveStatic } from "./src/utils"
import { $ } from "bun"


await import('node:fs').then(async fs => {
    await $`./mkflag $(whoami) "$ICQ_FLAG"`.quiet()
    fs.openSync('./flag.txt', 'r')
    await $`./rmflag`.quiet()
})

const server = Bun.serve({
    port: 3031,
    async fetch(req) {
        const url = new URL(req.url)
        const pathname = url.pathname

        if (pathname === "/status" && req.method === "GET") {
            return Response.json({
                platform: process.platform,
                cwd: process.cwd(),
                cmdline: (await Bun.file("/proc/self/cmdline").text()).replace(/\0/g, " ").trim(),
                pid: process.pid,
                resource_usage: {
                    cpu: process.cpuUsage(),
                    memory: process.memoryUsage(),
                }
            })
        }

        const rest_path = restPath(url, "/api") || ''
        if (rest_path === "/run" && req.method === "POST" && isContentType(req, 'application/x-www-form-urlencoded')) {
            let body = await parseBody(req);
            let code = body.code as string | undefined
            let ext = body.ext as string | undefined
            let input = body.input as string | undefined
            if (typeof code === 'undefined') return Res.JSON.InvalidRequest()
            if (!(ext && supportExtensions.includes(ext))) return Res.JSON.InvalidRequest()
            if (!input) input = ""
            let result = await runCode(code, input, { submit: false, extention: ext })
            return Response.json({
                code: 200,
                result: result
            })
        }
        if (rest_path === "/submit" && req.method === "POST" && isContentType(req, 'application/x-www-form-urlencoded')) {
            let body = await parseBody(req);
            let code = body.code as string | undefined
            let ext = body.ext as string | undefined
            if (typeof code === 'undefined') return Res.JSON.InvalidRequest()
            if (!(ext && supportExtensions.includes(ext))) return Res.JSON.InvalidRequest()
            let result = await runCode(code, '', { submit: true, extention: ext })
            return Response.json({
                code: 200,
                result: result
            })
        }
        if (rest_path === "/upload" && req.method === "OPTIONS") {
            return Res.OK()
        }
        if (rest_path === "/upload" && req.method === "POST" && isContentType(req, 'multipart/form-data')) {
            let formdata = await parseBody(req) as FormData
            let file_content = formdata.get("file") as Blob | undefined
            let entry_fn = formdata.get("entry") as string | undefined
            if (!file_content || !entry_fn) return Res.JSON.InvalidRequest()
            let resp = await handleUnArchive(file_content, entry_fn)
            return resp
        }
        if (/^\/problem\/\d+$/.test(rest_path) && req.method === "GET") {
            let id = /^\/problem\/(\d+)$/.exec(rest_path)![1]
            let problem_id = parseInt(id)
            return Response.json(getProblemInfo(problem_id))
        }
        if (/^\/run\/[\w\-]+$/.test(rest_path) && req.method === "POST" && isContentType(req, 'application/x-www-form-urlencoded')) {
            let body = await parseBody(req);
            let code = body.code as string | undefined
            let input = body.input as string | undefined
            // if (!code) return Res.JSON.InvalidRequest()
            if (!input) input = ""
            let id = /^\/run\/([\w\-]+)$/.exec(rest_path)![1]
            let result = await runEntry(id, code, input, false)
            return Response.json({
                code: 200,
                result: result
            })
        }
        if (/^\/submit\/[\w\-]+$/.test(rest_path) && req.method === "POST" && isContentType(req, 'application/x-www-form-urlencoded')) {
            let body = await parseBody(req);
            let code = body.code as string | undefined
            // if (!code) return Res.JSON.InvalidRequest()
            let id = /^\/submit\/([\w\-]+)$/.exec(rest_path)![1]
            let result = await runEntry(id, code, '', true)
            return Response.json({
                code: 200,
                result: result
            })
        }
        if (/^\/cancel\/[\w\-]+$/.test(rest_path) && req.method === "POST" && isContentType(req, 'application/x-www-form-urlencoded')) {
            let id = /^\/cancel\/([\w\-]+)$/.exec(rest_path)![1]
            let resp = await handleDelUploadedArchive(id)
            return resp
        }

        // mount static files
        let s = await resolveStatic("./static", pathname)
        if (s) return s
        s = await resolveStatic("./web/dist", pathname)
        if (s) return s

        return Res.NotFound()
    },
    error(e) {
        console.error(e)
        return Res.NotFound()
    },
})

console.log(`Server is running on ${server.url}`)