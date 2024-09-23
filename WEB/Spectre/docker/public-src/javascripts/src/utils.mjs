export function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
        .replace(/ /g, "&nbsp;");
}

/**
 * @param {Object} options
 * @param {string} options.method
 * @param {string} options.path
 * @param {string} [options.contentType]
 * @param {string} [options.body]
 * @param {boolean} [options.async]
 * @param {(xhr: XMLHttpRequest) => any} [options.onerror]
 * @param {(xhr: XMLHttpRequest) => any} [options.onabort]
 * @param {(xhr: XMLHttpRequest) => any} [options.callback]
 */
export function sendXMLHTTPRequest(options) {
    const xhr = new XMLHttpRequest();
    let opt_async = typeof options.async === "boolean" ? options.async : true
    xhr.open(options.method, options.path, opt_async);
    let contentTypeNeededMethods = ["POST", "PUT", "PATCH"];
    if (contentTypeNeededMethods.includes(options.method)) {
        xhr.setRequestHeader("Content-Type", options.contentType || "application/x-www-form-urlencoded");
    }
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            if (options.callback) options.callback(xhr);
        }
    }
    if (options.onabort) xhr.onabort = () => options.onabort(xhr);
    if (options.onerror) xhr.onerror = () => options.onerror(xhr);
    xhr.send(options.body);
}