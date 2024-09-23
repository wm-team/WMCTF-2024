import { $ } from 'bun';
import { genRndString, sha256, fitpath } from './utils';
import * as uuid from 'uuid';

type ExecResult = {
    error: boolean;
    etype?: "RTE" | "TLE" | "SE" | "CE" | "UKE";
    stderr: string;
    stdout: string;
    check?: boolean;
}
type RunEntries = {
    dir: string;
    file: string;
}
type ProblemInfo = {
    title: string;
    description: string;
}
type RunCodeOptions = {
    submit: boolean;
    del: boolean;
    extention: string;
    targetFile?: string;
}

const defaultRunCodeOpts = {
    submit: false,
    del: true,
    extention: "js"
}

export const supportExtensions = ['js', 'ts']

const challengeAnswer = genRndString(64)

const zipRunEntries = new Map<string, RunEntries>()

const problemStorage = new Map<number, ProblemInfo>(Object.entries({
    0: {
        title: "SHA256 Reverse",
        description: `Find the string whose SHA256 hash is \`${sha256(challengeAnswer)}\`.`
    }
}).map(([k, v]) => [parseInt(k), v]))

export function getProblemInfo(id: number) {
    let pinfo = problemStorage.get(id)
    if (!pinfo) { return { code: 404, data: { title: "Unkown", description: "Nothing here" } } }
    return { code: 200, data: pinfo }
}

async function _runCode(code: string, input: string, options: RunCodeOptions): Promise<ExecResult> {
    const opts = options
    if (!opts.targetFile) {
        let tempFnTmpl = `run.XXXXXXXXXX.${opts.extention}`
        opts.targetFile = fitpath(await $`mktemp -t ${tempFnTmpl} | tr -d '\n'`.quiet().text())
    }
    const TMPFILE = opts.targetFile
    let tmpl = await Bun.file("./template/tmpl.run." + opts.extention).text()
    await Bun.write(
        TMPFILE,
        tmpl.replace(/{{ *input *}}/g,
            '[' + input/* .replace(/\r?\n$/, '') */
                .split(/\r?\n/)
                .map(l => JSON.stringify(l))
                .join(",") + ']')
            .replace(/{{ *code *}}/g, code),
        { createPath: true })

    let p = await $`timeout 5s deno run ${TMPFILE}`.nothrow().quiet()
    let result: ExecResult = {
        error: p.exitCode !== 0,
        stderr: p.stderr.toString(),
        stdout: p.stdout.toString(),
    }
    if (result.error) {
        result.etype = p.exitCode === 124 ? "TLE" : "RTE"
    }
    if (opts.submit) {
        result.check = p.exitCode === 0 && sha256(p.stdout.toString().trim()) === sha256(challengeAnswer)
    }
    if (opts.del) { await $`rm ${TMPFILE}`.nothrow() }
    return result;
}

export async function runCode(code: string, input: string, options?: Partial<RunCodeOptions>): Promise<ExecResult> {
    const opts: RunCodeOptions = Object.assign({}, defaultRunCodeOpts, options)
    if (opts.targetFile) {
        // automatically detect extention
        if (typeof options?.extention === 'undefined') {
            const ext = opts.targetFile.split('/').pop()?.split('.').pop()
            // ensure extention is supported
            if (ext && supportExtensions.includes(ext)) opts.extention = ext
            else {
                let ret: ExecResult = {
                    error: true,
                    etype: "CE",
                    stderr: `\x1b[33mUnsupported extention:\x1b[0m ${ext}`,
                    stdout: ""
                }
                if (options?.submit) { ret.check = false }
                return ret
            }
        }
    }
    try {
        return await _runCode(code, input, opts)
    } catch (e: any) {
        let ret: ExecResult = {
            error: true,
            etype: e ? "SE" : "UKE",
            stderr: e ? e.toString() : '',
            stdout: ""
        }
        if (options?.submit) { ret.check = false }
        return ret
    }
}

export async function runEntry(id: string, code?: string, input?: string, submit: boolean = false): Promise<ExecResult> {
    if (!zipRunEntries.has(id)) { return { error: true, etype: "SE", stderr: `Cannot find id ${id}`, stdout: "", check: false } }
    let entry = zipRunEntries.get(id)
    if (!entry) { return { error: true, etype: "SE", stderr: `Cannot find id ${id}`, stdout: "", check: false } }

    let p = await $`test -f ${entry.file}`.nothrow().quiet()
    if (p.exitCode !== 0) {
        zipRunEntries.delete(id)
        await $`rm -rf ${entry.dir}`.nothrow()
        return { error: true, etype: "CE", stderr: `Cannot find entry file ${entry.file}`, stdout: "", check: false }
    }
    if (!code) { code = await Bun.file(entry.file).text() }
    if (!input) { input = "" }
    let r = await runCode(code, input, { submit, del: false, targetFile: entry.file })
    // zipRunEntries.delete(id)
    // await $`rm -rf ${entry.dir}`.nothrow()
    return r
}

export async function handleDelUploadedArchive(id: string) {
    let entry = zipRunEntries.get(id)
    if (!entry) {
        return Response.json({
            code: 200,
            message: "miss"
        }, { status: 200 })
    }
    zipRunEntries.delete(id)
    let p = await $`rm -rf ${entry.dir}`.nothrow().quiet()
    if (p.exitCode !== 0) {
        console.error(p.stderr.toString())
        return Response.json({
            code: 500,
            message: "fail"
        }, { status: 500 })
    }
    return Response.json({
        code: 200,
        message: "success"
    }, { status: 200 })
}

export async function handleUnArchive(file: Blob, entryFile: string) {
    // test file type (zip)
    const TMPFILE = fitpath(await $`mktemp -t upload.XXXXXXXXXX.zip | tr -d '\n'`.quiet().text())
    await Bun.write(TMPFILE, file, { createPath: true })
    let expectedTypeOutput = `${TMPFILE}: Zip archive data, `
    let p = await $`file ${TMPFILE}`.nothrow().quiet()
    let testTypeOutput = p.stdout.toString()
    if (p.exitCode !== 0 || !testTypeOutput.startsWith(expectedTypeOutput)) {
        await $`rm ${TMPFILE}`.nothrow()
        return Response.json({ code: 403, message: "Invalid file type" }, { status: 403 })
    }

    // unzip file
    const TMPDIR = fitpath(await $`mktemp -d -t upload.XXXXXXXXXX | tr -d '\n'`.quiet().text())
    p = await $`unzip -d ${TMPDIR} ${TMPFILE}`.nothrow().quiet()
    if (p.exitCode !== 0) {
        await $`rm -rf ${TMPDIR}`.nothrow()
        return Response.json({ code: 500, message: "Failed to unzip file" }, { status: 500 })
    }

    // is entry file exists
    // let absTmpDir = await $`realpath ${TMPDIR}`.quiet().text()
    let absTmpDir = TMPDIR
    let entryPath = `${TMPDIR}/${entryFile}`
    p = await $`realpath -m ${entryPath} | tr -d '\n'`.nothrow().quiet()
    let absEntryPath = p.text()
    if (p.exitCode !== 0 || !absEntryPath.startsWith(absTmpDir)) {
        return Response.json({ code: 403, message: "Forbidden" }, { status: 403 })
    }
    const entryId = uuid.v4()
    zipRunEntries.set(entryId, { dir: TMPDIR, file: absEntryPath })
    p = await $`test -f ${absEntryPath}`.nothrow().quiet()
    const PLACEHOLDER = "/* Please write your entry file here */\n"
    if (p.exitCode !== 0) {
        await Bun.write(absEntryPath, PLACEHOLDER, { createPath: true })
        return Response.json({
            code: 200,
            data: { id: entryId, absent: true, content: PLACEHOLDER }
        }, { status: 200 })
    }
    else {
        // read file
        let content = await Bun.file(absEntryPath).text()
        return Response.json({
            code: 200,
            data: { id: entryId, absent: false, content }
        }, { status: 200 })
    }
}