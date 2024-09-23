type XhrOptions = {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: XMLHttpRequestBodyInit;
    withCredentials?: boolean;
    callback?: (xhr: XMLHttpRequest) => void;
    onabort?: (xhr: XMLHttpRequest) => void;
    onerror?: (ev: ProgressEvent, xhr: XMLHttpRequest) => void;
};

const defaultOpts: Partial<XhrOptions> = {
    method: 'GET',
    headers: {},
    body: '',
    withCredentials: false,
    callback: () => { },
    onabort: () => { },
    onerror: () => { },
};

export function replaceParam(uri: string, param: { [k: string]: any }) {
    let res = uri
    for (let key in param) {
        res = uri.replace(new RegExp(`/${':' + key}(\/|$)`), '/' + encodeURIComponent(param[key]) + '$1')
    }
    return res
}

export default function sendXhr(options: XhrOptions) {
    const opts = Object.assign({}, defaultOpts, options) as Required<XhrOptions>;

    const xhr = new XMLHttpRequest();
    xhr.open(opts.method, opts.url, true);
    xhr.withCredentials = opts.withCredentials;

    if (['POST', 'PUT', 'PATCH'].includes(opts.method) && typeof options.headers?.['Content-Type'] === 'undefined') {
        xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    }
    Object.entries(opts.headers).forEach(([name, value]) => {
        xhr.setRequestHeader(name, value);
    });
    xhr.onreadystatechange = () => {
        if (xhr.readyState === XMLHttpRequest.DONE) {
            opts.callback(xhr);
        }
    };
    xhr.onabort = () => opts.onabort(xhr);
    xhr.onerror = (ev) => opts.onerror(ev, xhr);
    xhr.send(opts.body);
    return xhr;
}