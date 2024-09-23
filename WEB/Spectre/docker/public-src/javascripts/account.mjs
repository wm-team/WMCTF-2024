import '../stylesheets/account.scss';

import { sha256, str2hex, hex2str, xorHex } from "./src/crypto.mjs"

const routeType = window.location.pathname.startsWith('/account/login') ? 'login' : 'signup';
let on_submit = false;

document.addEventListener("DOMContentLoaded", function () {
    const btn = document.getElementsByName('submit')[0];
    const usernameEl = document.getElementsByName('username')[0];
    const passwordEl = document.getElementsByName('password')[0];
    const rememberEl = document.getElementsByName('remember-me')[0];
    const messageEl = document.getElementById('account-tips');

    passwordEl.oncontextmenu = function () { return false; };
    passwordEl.oncopy = function () { return false; };
    passwordEl.oncut = function () { return false; };
    // const BTN_TEXT = btn.innerText;

    const urlobj = new URL(window.location.href);
    const next = urlobj.searchParams.get('next');

    if (routeType === 'login') {
        try {
            const data = window.name ? JSON.parse(decodeURIComponent(atob(window.name))) : undefined;
            if (data) {
                usernameEl.value = data.username;
                passwordEl.value = hex2str(xorHex(data.password, new Uint8Array([0xe8, 0x15, 0x11, 0x45, 0x14])));
            }
        } catch (e) { }
    }
    window.name = '';

    if (routeType === 'login') {
        document.querySelector('a[href="/account/signup"]').href += (next ? `?next=${encodeURIComponent(next)}` : '');
    } else {
        document.querySelector('a[href="/account/login"]').href += (next ? `?next=${encodeURIComponent(next)}` : '');
    }

    function printMessage(msg, type, prevent = false) {
        on_submit = true;
        btn.classList.remove('loading');
        messageEl.innerText = '';
        messageEl.classList.forEach((v) => {
            if (v.startsWith("text-")) messageEl.classList.remove(v);
        });
        if (type) messageEl.classList.add("text-" + type);
        messageEl.innerText = msg;
        if (!prevent) on_submit = false;
    }

    btn.addEventListener('click', function () {
        if (on_submit) return;
        if (!usernameEl.value || !passwordEl.value) {
            printMessage('Empty field exists', "warning");
            return;
        }
        if (!/^[a-zA-Z0-9_]{6,20}$/.test(passwordEl.value)) {
            printMessage('Invalid format', "warning");
            return;
        }
        on_submit = true;
        btn.classList.add('loading');
        const xhr = new XMLHttpRequest();
        let path = window.location.pathname
        xhr.open('POST', path, true);
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4 && xhr.status === 200) {
                const res = JSON.parse(xhr.responseText);
                if (res.code === 200) {
                    printMessage('Success', "success", true);
                    btn.innerText = 'Redirecting';
                    btn.classList.add('btn-success')
                    setTimeout(() => {
                        if (routeType === 'signup') {
                            window.name = btoa(encodeURIComponent(JSON.stringify({
                                username: usernameEl.value,
                                password: xorHex(str2hex(passwordEl.value), new Uint8Array([0xe8, 0x15, 0x11, 0x45, 0x14]))
                            })));
                            window.location.href = '/account/login' + (next ? `?next=${encodeURIComponent(next)}` : '');
                        } else {
                            window.location.href = next || '/';
                        }
                    }, 800)
                } else {
                    if (routeType === 'login' && res.code === 401) {
                        printMessage('Invalid username or password', "error");
                    } else {
                        printMessage(`${res.message} (${res.code})`, "error");
                    }
                }
            }
        }
        xhr.onabort = xhr.onerror = function () {
            printMessage('Failed', "error");
        }
        let args = {
            'username': usernameEl.value,
            'password': sha256(passwordEl.value),
            'remember': rememberEl ? (rememberEl.checked ? 1 : 0) : undefined
        }
        let dataArray = []
        for (let key in args) {
            if (args[key] !== undefined) {
                dataArray.push(`${key}=${encodeURIComponent(args[key])}`);
            }
        }
        xhr.send(dataArray.join('&'));
    })
})