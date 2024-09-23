import { escapeHtml, sendXMLHTTPRequest } from "../src/utils.mjs";

let on_submit = false;
let on_delete = false;

// const BTN_CLASSES_RESERVE = ['btn-primary', 'btn-danger', 'btn-warning', 'btn-success', 'btn-info', 'btn-secondary', 'btn-link'];

/**
 * @param {Event} e
 */
function evt_only_you(e) {
    const btn = e.target;
    const table = document.getElementById('submission-table');
    const noResultEl = document.getElementById('empty-result');
    const noFilterResultEl = document.getElementById('empty-filter');
    if (btn.classList.contains('active')) {
        // active -> inactive
        let uid = btn.dataset.uid;
        const all = table.querySelectorAll('tr[data-uid]')
        all.forEach(tr => {
            if (tr.dataset.uid !== uid) {
                tr.style.display = '';
            }
        })
        if (!noFilterResultEl.classList.contains('none-display')) {
            // hide
            noFilterResultEl.classList.add('none-display')
        }
        if (all.length === 0) {
            // move to top
            noResultEl.insertAdjacentElement('afterend', noFilterResultEl);
            // show
            noResultEl.classList.remove('none-display');
        }
        btn.classList.remove('active');
    } else {
        // inactive -> active
        let uid = btn.dataset.uid;
        const all = table.querySelectorAll('tr[data-uid]')
        let hide_cnt = 0;
        all.forEach(tr => {
            if (tr.dataset.uid !== uid) {
                hide_cnt++;
                tr.style.display = 'none';
            }
        })
        if (!noResultEl.classList.contains('none-display')) {
            // hide
            noResultEl.classList.add('none-display')
        }
        if (hide_cnt === all.length) {
            // move to top
            noFilterResultEl.insertAdjacentElement('afterend', noResultEl);
            // show
            noFilterResultEl.classList.remove('none-display')
        }
        btn.classList.add('active');
    }
}

/**
 * @param {Event} e
 */
function evt_op_delete(e) {
    if (on_delete) return;
    on_delete = true;

    const btn = e.target;
    let uuid = btn.dataset.uuid;

    let colorMap = {
        "error": "#e85600",
        "warning": "#e85600",
    }

    function printMessage(msg, type) {
        btn.classList.remove('loading');
        if (type === "success") { on_delete = false; return; }
        if (type === "error") console.error("[Delete] " + msg);
        if (type === "warning") console.warn("[Delete] " + msg);
        on_delete = true;
        if (Object.prototype.hasOwnProperty.call(colorMap, type)) {
            btn.style.color = colorMap[type];
            setTimeout(() => {
                btn.style.color = '';
                on_delete = false;
            }, 1000);
        } else {
            on_delete = false;
        }
    }

    btn.classList.add('loading');
    const preLineCnt = (() => {
        let lines = document.querySelectorAll('tr[data-type=line]')
        let cnt = 0;
        for (let line of lines) {
            if (line.style.display === '') ++cnt;
        }
        return cnt;
    })();
    sendXMLHTTPRequest({
        method: 'DELETE',
        path: `/s/${uuid}`,
        callback: function (xhr) {
            const res = JSON.parse(xhr.responseText);
            if (res.code === 200) {
                printMessage('Success', "success");
                let tr = btn.parentElement.parentElement;
                tr.remove();
                if (preLineCnt === 1) {
                    const only_you_btn = document.getElementsByName('only-you')[0];
                    if (only_you_btn) {
                        let isActive = only_you_btn.classList.contains('active');
                        const noResultEl = document.getElementById('empty-result');
                        const noFilterResultEl = document.getElementById('empty-filter');
                        if (isActive) {
                            // move to top
                            noFilterResultEl.insertAdjacentElement('afterend', noResultEl);
                            // show
                            noFilterResultEl.classList.remove('none-display');
                        } else {
                            // move to top
                            noResultEl.insertAdjacentElement('afterend', noFilterResultEl);
                            // show
                            noResultEl.classList.remove('none-display');
                        }
                    } else {
                        // show
                        document.getElementById('empty-result').classList.remove('none-display');
                    }
                }

            } else {
                printMessage(`${res.message} (${res.code})`, "error");
            }
        },
        onabort: function () {
            printMessage('Failed', "error");
        },
        onerror: function () {
            printMessage('Failed', "error");
        }
    });
}

/**
 * @param {Event} e
 */
function evt_submit(e) {
    if (on_submit) return;
    on_submit = true;

    const btn = e.target;
    const contentEl = document.getElementById('typearea');
    const BTN_TEXT = btn.innerText;

    function printMessage(msg, type, prevent = false) {
        on_submit = true;
        btn.innerText = msg;
        if (type) btn.classList.add("btn-" + type);
        btn.classList.remove('loading');
        if (!prevent) {
            setTimeout(() => {
                if (type) btn.classList.remove("btn-" + type);
                setTimeout(() => {
                    btn.innerText = BTN_TEXT;
                    on_submit = false;
                }, 100)
            }, 1000);
        }
    }
    btn.classList.add('loading');

    sendXMLHTTPRequest({
        method: 'POST',
        path: '/submit',
        body: `content=${encodeURIComponent(escapeHtml(contentEl.innerText))}`,
        callback: function (xhr) {
            const res = JSON.parse(xhr.responseText);
            if (res.code === 200) {
                printMessage('Success', "success", true);
                setTimeout(() => {
                    window.location.href = `/s/${res.uuid}`;
                }, 1000);
            } else {
                printMessage(`${res.message} (${res.code})`, "error");
            }
        },
        onabort: function () {
            printMessage('Failed', "error");
        },
        onerror: function () {
            printMessage('Failed', "error");
        }
    });
}

/**
 * @param {Event} e
 */
function evt_delete(e) {
    if (on_delete) return;
    on_delete = true;

    const btn = e.target;
    const BTN_TEXT = btn.innerText;

    function printMessage(msg, type, prevent = false) {
        on_delete = true;
        btn.innerText = msg;
        if (type) btn.classList.add("btn-" + type);
        btn.classList.remove('loading');
        if (!prevent) {
            setTimeout(() => {
                if (type) btn.classList.remove("btn-" + type);
                setTimeout(() => {
                    btn.innerText = BTN_TEXT;
                    on_delete = false;
                }, 100);
            }, 1000);
        }
    }
    btn.classList.add('loading');

    sendXMLHTTPRequest({
        method: 'DELETE',
        path: window.location.pathname,
        callback: function (xhr) {
            const res = JSON.parse(xhr.responseText);
            if (res.code === 200) {
                printMessage('Deleted', "success", true);
                setTimeout(() => {
                    window.location.href = '/submit';
                }, 1000);
            } else {
                printMessage(`${res.message} (${res.code})`, "error");
            }
        },
        onabort: function () {
            printMessage('Failed', "error");
        },
        onerror: function () {
            printMessage('Failed', "error");
        }
    });
}

const btnEvts = {
    "go-back": (e) => { window.history.back(); },
    "create-new": (e) => { window.location.href = '/submit'; },
    "logout": (e) => { window.location.href = '/account/logout'; },
    "list": (e) => { window.location.href = '/list'; },
    'goto-bot': (e) => {
        let uuid = e.target.dataset.uuid;
        window.location.href = '/bot' + `?uuid=${encodeURIComponent(uuid)}`;
    },
    "only-you": evt_only_you,
    "op-see": (e) => {
        const btn = e.target;
        const uuid = btn.dataset.uuid;
        window.location.href = `/s/${uuid}`;
    },
    "op-del": evt_op_delete,
    "submit": evt_submit,
    "delete": evt_delete
}

document.addEventListener("DOMContentLoaded", function () {
    for (const key in btnEvts) {
        document.getElementsByName(key).forEach(btn => {
            btn.addEventListener('click', btnEvts[key]);
        })
    }
})