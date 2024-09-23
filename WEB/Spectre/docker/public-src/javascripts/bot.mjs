import '../stylesheets/bot.scss';
import './components/event.mjs';

import { EventSourcePolyfill } from 'event-source-polyfill';
import { b64encode } from './src/crypto.mjs';


let on_requesting = false;
let on_counting = false;
let on_printing = false;

document.addEventListener("DOMContentLoaded", function () {

    const btn = document.querySelector("[name='commit-bot']");
    const progressEl = document.getElementById("progress");
    const uuidEl = document.querySelector("[name='uuid']");
    const BTN_TEXT = btn.innerText;
    const TOT_COUNTDOWN = parseInt(getComputedStyle(document.documentElement).getPropertyValue('--progress-countdown-total'));
    const TRANSITION = getComputedStyle(progressEl).getPropertyValue('transition');
    let url_uuid = new URLSearchParams(window.location.search).get("uuid");
    if (url_uuid) uuidEl.value = url_uuid;
    const captchaEnabled = document.querySelector("[data-captcha]").dataset.captcha === "true";

    let countdown = TOT_COUNTDOWN;
    let countdown_itvarray = [];
    function setProgress(countdown) {
        if (!progressEl.classList.contains('tooltip')) {
            progressEl.classList.add('tooltip');
        }
        if (!btn.classList.contains('disabled')) {
            btn.classList.add('disabled');
        }
        if (!btn.parentElement.classList.contains('cursor-wait')) {
            btn.parentElement.classList.add('cursor-wait');
        }
        btn.classList.remove('loading');
        progressEl.style.transition = TRANSITION;
        let count = TOT_COUNTDOWN - countdown;
        document.documentElement.style.setProperty('--progress-count', count);
        let percent = parseInt(count / TOT_COUNTDOWN * 100);
        progressEl.setAttribute('data-tooltip', `${percent}%`);
        btn.innerText = countdown;
    }
    function resetProgress(controlBtn = false) {
        countdown_itvarray.forEach(clearInterval);
        progressEl.classList.remove('tooltip');
        if (controlBtn && !on_printing) {
            btn.classList.remove('disabled', 'loading');
            btn.parentElement.classList.remove('cursor-wait');
            btn.innerText = BTN_TEXT;
        }
        progressEl.style.transition = 'none';
        document.documentElement.style.setProperty('--progress-count', 0);
    }
    function printMessage(msg, type, prevent = false) {
        on_requesting = true;
        on_printing = true;
        btn.innerText = msg;
        if (type) btn.classList.add("btn-" + type);
        btn.classList.remove('disabled', 'loading');
        btn.parentElement.classList.remove('cursor-wait');
        setTimeout(() => {
            if (type) btn.classList.remove("btn-" + type);
            setTimeout(() => {
                btn.innerText = BTN_TEXT;
                if (!prevent) on_requesting = false;
                on_printing = false;
            }, 100)
        }, 1000);
    }
    function startCountDown(force = false, cancel_request = true) {
        if (on_counting && !force) return;
        on_counting = true;

        countdown = TOT_COUNTDOWN;
        countdown_itvarray.forEach(clearInterval);
        countdown_itvarray = [];
        // setProgress(countdown);
        // --countdown;
        let itvid = setInterval(() => {
            if (countdown <= 0) {
                clearInterval(itvid);
                resetProgress(true);
                on_counting = false;
                if (cancel_request) on_requesting = false;
                return;
            }
            setProgress(countdown);
            --countdown;
        }, 1000);
        countdown_itvarray.push(itvid);
    }
    let table_memory = [];
    function beautifyPrintTable(ms, stage, title, first = false) {
        if (first) table_memory = [];
        table_memory.push({
            "Time Cost (s)": ms / 1000,
            "Stage": stage,
            "Page Title": title
        })
        let print_table = table_memory;
        if (first) {
            print_table = [...table_memory, {
                "Time Cost (s)": undefined,
                "Stage": undefined,
                "Page Title": undefined
            }]
        }
        console.clear();
        console.table(print_table);
    }
    function sendRequest(path, headers) {
        const sse = new EventSourcePolyfill(path, { withCredentials: true, headers: headers });
        sse.addEventListener("message", function (e) {
            const res = JSON.parse(e.data);
            if (res.code === 201) {
                // start
                startCountDown(true);
                beautifyPrintTable(res.data.delta, res.message.toLowerCase(), res.data.title, true)
            } else if (res.code === 200) {
                // processing
                beautifyPrintTable(res.data.delta, res.message.toLowerCase(), res.data.title)
            } else if (res.code === 202) {
                // done
                beautifyPrintTable(res.data.delta, res.message.toLowerCase(), res.data.title)
            }
        });
        sse.addEventListener("res:error", function (e) {
            sse.close();
            const res = JSON.parse(e.data);
            resetProgress();
            printMessage(`${res.message} (${res.code})`, "error");
            console.error("[SSE]", res);
        });
        sse.addEventListener("res:done", function (e) {
            sse.close();
            // const res = JSON.parse(e.data);
            resetProgress();
            printMessage("Success", "success");
        });
        sse.onerror = function (e) {
            sse.close();
            const res = JSON.parse(e.data);
            resetProgress();
            printMessage("Connection Error", "error");
            console.error("[SSE]", res);
        }
    }
    function commit() {
        if (on_requesting) return;
        on_requesting = true;
        btn.classList.add('loading');
        let prefix = document.querySelector("[name='url-prefix']").innerText;
        let uuid = uuidEl.value;
        let cf_response = document.querySelector("[name='cf-turnstile-response']")?.value || '';
        if (!uuid) return printMessage("UUID is required", "error");
        if (captchaEnabled && !cf_response) return printMessage("CAPTCHA is required", "error");
        let headers = {
            "X-Bot-Visit": b64encode(prefix + uuid),
            "Cf-Turnstile-Response": b64encode(cf_response)
        }
        sendRequest(window.location.pathname, headers);
    }
    document.querySelector("[name='commit-bot']").addEventListener("click", commit);
})