import { $ } from 'bun';


export function genRndHex(n: number = 0) {
    return [...Array(n)].map(() => Math.floor(Math.random() * 16).toString(16)).join('')
}

export function genRndString(n: number = 0) {
    return [...Array(n)].map(() => Math.floor(Math.random() * 36).toString(36)).join('')
}

export function sha256(input: string) {
    let hasher = new Bun.CryptoHasher("sha256")
    hasher.update(input)
    return hasher.digest("hex")
}

export function restPath(url: URL, pathPrefix: string): string | undefined {
    let { pathname } = url
    let fmt_path = pathname.endsWith('/') ? pathname : pathname + '/'
    if (fmt_path.startsWith(pathPrefix.endsWith('/') ? pathPrefix : pathPrefix + '/')) {
        return pathname.substring(pathPrefix.length)
    }
    return undefined
}

export function fitpath(p: string) {
    if (process.platform !== "win32") { return p }
    if (/^\/[a-zA-Z]\//.test(p)) {
        return p.replace(/^\/([a-zA-Z])\//, "$1:/")
    }
    if (/^\/tmp\//.test(p)) {
        let tmpdir = process.env["TEMP"]
        if (!tmpdir) { return p }
        tmpdir = tmpdir.replace(/\\/g, "/").replace(/\/$/, "")
        return p.replace(/^\/tmp\//, tmpdir + "/")
    }
    return p
}

export async function parseBody(req: Request): Promise<any> {
    if (!['POST', 'PUT', 'PATCH'].includes(req.method)) {
        return {}
    }
    let rawContentType = req.headers.get("content-type")
    let contentType = rawContentType ? rawContentType.split(";")[0].trim() : ""
    if (contentType === "application/json") {
        return await req.json()
    } else if (contentType === "application/x-www-form-urlencoded") {
        return Object.fromEntries(new URLSearchParams(await req.text()))
    } else if (contentType === "multipart/form-data") {
        return await req.formData()
    }
    return {}
}

export function isContentType(req: Request, t: string): boolean {
    if (!req.headers.has("content-type")) return false
    let contentTypes = req.headers.get("content-type")?.split(",") || []
    return contentTypes.some(ct => ct.split(";")[0].trim() === t)
}

export const Res = {
    json: (status: number, message: any) => Response.json({ code: status, message }, { status }),
    throw: (status: number, message: string) => new Response(message, { status }),
    JSON: {
        NotFound: () => Res.json(404, "Not Found"),
        InvalidRequest: () => Res.json(400, "Invalid Request"),
        Forbidden: () => Res.json(403, "Forbidden"),
        MediaTypeNotSupported: () => Res.json(415, "Media Type Not Supported"),
        MethodNotAllowed: () => Res.json(405, "Method Not Allowed"),
    },
    Redirect: (url: string, status = 302) => new Response(`Redirect to <a href="${url}">${url}</a>`, {
        status, headers: {
            "Location": url
        }
    }),
    OK: () => new Response("OK", { status: 200 }),
    NotFound: () => new Response("Not Found", { status: 404 }),
    InvalidRequest: () => new Response("Invalid Request", { status: 400 }),
    Forbidden: () => new Response("Forbidden", { status: 403 }),
    MediaTypeNotSupported: () => new Response("Media Type Not Supported", { status: 415 }),
    MethodNotAllowed: () => new Response("Method Not Allowed", { status: 405 }),
}

export function sniffMimeType(filename: string) {
    let ext = /.\.(\w+)$/.exec(filename)?.[1] || ''
    if (/^html?$/.test(ext)) return 'text/html'
    if (/^css$/.test(ext)) return 'text/css'
    if (/^js$/.test(ext)) return 'application/javascript'
    if (/^json$/.test(ext)) return 'application/json'
    if (/^xml$/.test(ext)) return 'application/xml'
    if (/^txt$/.test(ext)) return 'text/plain'
    if (/^png$/.test(ext)) return 'image/png'
    if (/^jpe?g$/.test(ext)) return 'image/jpeg'
    if (/^gif$/.test(ext)) return 'image/gif'
    if (/^svg$/.test(ext)) return 'image/svg+xml'
    if (/^ico$/.test(ext)) return 'image/x-icon'
    return 'application/octet-stream'
}

const absCacheMap = new Map<string, string>()
const FALLBACK_FILES = ["index.html", "index.htm"]
export async function resolveStatic(base: string, path: string, fallback_files: string[] = FALLBACK_FILES) {
    // parse to absolute path
    let absolute_base = absCacheMap.get(base)
    if (typeof absolute_base === 'undefined') {
        absolute_base = fitpath(await $`realpath ${base} | tr -d '\n'`.text())
            .replace(/\/*$/, "/")
        absCacheMap.set(base, absolute_base)
    }
    // resolve path
    if (!absolute_base.endsWith('/')) absolute_base += '/'
    if (!path.startsWith('/')) path = '/' + path
    let fp = `${absolute_base}${path.substring(1)}`
    let abs_fp = await $`realpath -m ${fp} | tr -d '\n'`.quiet().text()
    if ((abs_fp + '/').startsWith(absolute_base)) {
        let ptype = (await $`sh src/pathtype.sh ${abs_fp}`.nothrow().quiet()).stdout.toString()
        if (ptype === 'file') {
            // found file
            return new Response(Bun.file(abs_fp), {
                status: 200,
                headers: {
                    "Content-Type": sniffMimeType(path)
                }
            })
        } else if (ptype === 'dir') {
            // found directory, try to find fallback file
            let abs_fpd = abs_fp.replace(/\/*$/, "/")
            for (let f of fallback_files) {
                let testf = await $`test -f ${abs_fpd}${f}`.nothrow().quiet()
                if (testf.exitCode === 0) {
                    // hit fallback
                    if (path.endsWith('/')) {
                        return new Response(Bun.file(`${abs_fpd}${f}`), {
                            status: 200,
                            headers: {
                                "Content-Type": sniffMimeType(f)
                            }
                        })
                    } else {
                        return Res.Redirect(path + '/', 301)
                    }
                }
            }
            // return Res.NotFound()
        }
    }
}