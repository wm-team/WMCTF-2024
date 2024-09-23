// https://github.com/rburns/ansi-to-html/blob/master/lib/ansi_to_html.js
'use strict';
import * as entities from 'entities';

type ColorsType = { [k: number]: string };
type CodeCallType = { [k: string]: () => string | number | undefined };

type StickyStackType = {
    token: string;
    data: string;
    category: string | null;
};

type Callback = (token: string, data: string, rawAnsi?: string) => any;
type CodeLike = string | number;

type Options = {
    /** The default foreground color used when reset color codes are encountered. */
    fg: string;
    /** The default background color used when reset color codes are encountered. */
    bg: string;
    /** Convert newline characters to `<br/>`. */
    newline: boolean;
    /** Generate HTML/XML entities. */
    escapeXML: boolean;
    /** Save style state across invocations of `toHtml()`. */
    stream: boolean;
    /** Can override specific colors or the entire ANSI palette. */
    colors: string[] | { [code: number]: string };
};

type Handler = {
    pattern: RegExp;
    sub: (m: string, g1: string) => string
}

const defaultOpts: Options = {
    fg: '#FFF',
    bg: '#000',
    newline: false,
    escapeXML: false,
    stream: false,
    colors: getDefaultColors()
};

function getDefaultColors() {
    const colors: ColorsType = {
        0: '#000',
        1: '#A00',
        2: '#0A0',
        3: '#A50',
        4: '#00A',
        5: '#A0A',
        6: '#0AA',
        7: '#AAA',
        8: '#555',
        9: '#F55',
        10: '#5F5',
        11: '#FF5',
        12: '#55F',
        13: '#F5F',
        14: '#5FF',
        15: '#FFF'
    };

    range(0, 5).forEach(red => {
        range(0, 5).forEach(green => {
            range(0, 5).forEach(blue => setStyleColor(red, green, blue, colors));
        });
    });

    range(0, 23).forEach(function (gray) {
        const c = gray + 232;
        const l = toHexString(gray * 10 + 8);

        colors[c] = '#' + l + l + l;
    });

    return colors;
}

function setStyleColor(red: number, green: number, blue: number, colors: ColorsType) {
    const c = 16 + (red * 36) + (green * 6) + blue;
    const r = red > 0 ? red * 40 + 55 : 0;
    const g = green > 0 ? green * 40 + 55 : 0;
    const b = blue > 0 ? blue * 40 + 55 : 0;

    colors[c] = toColorHexString([r, g, b]);
}

/**
 * Converts from a number like 15 to a hex string like 'F'
 */
function toHexString(num: number) {
    let str = num.toString(16);

    while (str.length < 2) {
        str = '0' + str;
    }

    return str;
}

/**
 * Converts from an array of numbers like [15, 15, 15] to a hex string like 'FFF'
 */
function toColorHexString(ref: [number, number, number]): string {
    const results = [];

    for (const r of ref) {
        results.push(toHexString(r));
    }

    return '#' + results.join('');
}

function generateOutput(stack: string[], token: string, data: string, rawAnsi: string, options: Options) {
    let result;
    if (token === 'text') {
        result = pushText(data, options);
    } else if (token === 'display') {
        result = handleDisplay(stack, data, rawAnsi, options);
    } else if (token === 'xterm256Foreground') {
        result = pushForegroundColor(stack, rawAnsi, options.colors[Number(data)]);
    } else if (token === 'xterm256Background') {
        result = pushBackgroundColor(stack, rawAnsi, options.colors[Number(data)]);
    } else if (token === 'rgb') {
        result = handleRgb(stack, rawAnsi, data);
    }

    return result;
}

function handleRgb(stack: string[], rawAnsi: string, data: string): string {
    data = data.substring(2).slice(0, -1);
    const operation = +data.substring(0, 2);

    const color = data.substring(5).split(';');
    const rgb = color.map(function (value) {
        return ('0' + Number(value).toString(16)).substr(-2);
    }).join('');

    return pushStyle(stack, rawAnsi, (operation === 38 ? 'color:#' : 'background-color:#') + rgb);
}

function handleDisplay(stack: string[], code: string | number, rawAnsi: string, options: Options) {
    code = parseInt(String(code), 10);

    const codeMap: CodeCallType = {
        [-1]: () => '<br/>',
        0: () => stack.length && resetStyles(stack),
        1: () => pushTag(stack, rawAnsi, 'b'),
        3: () => pushTag(stack, rawAnsi, 'i'),
        4: () => pushTag(stack, rawAnsi, 'u'),
        8: () => pushStyle(stack, rawAnsi, 'display:none'),
        9: () => pushTag(stack, rawAnsi, 'strike'),
        22: () => pushStyle(stack, rawAnsi, 'font-weight:normal;text-decoration:none;font-style:normal'),
        23: () => closeTag(stack, 'i'),
        24: () => closeTag(stack, 'u'),
        39: () => pushForegroundColor(stack, rawAnsi, options.fg),
        49: () => pushBackgroundColor(stack, rawAnsi, options.bg),
        53: () => pushStyle(stack, rawAnsi, 'text-decoration:overline')
    };

    let result;
    if (codeMap[code]) {
        result = codeMap[code]();
    } else if (4 < code && code < 7) {
        result = pushTag(stack, rawAnsi, 'blink');
    } else if (29 < code && code < 38) {
        result = pushForegroundColor(stack, rawAnsi, options.colors[code - 30]);
    } else if ((39 < code && code < 48)) {
        result = pushBackgroundColor(stack, rawAnsi, options.colors[code - 40]);
    } else if ((89 < code && code < 98)) {
        result = pushForegroundColor(stack, rawAnsi, options.colors[8 + (code - 90)]);
    } else if ((99 < code && code < 108)) {
        result = pushBackgroundColor(stack, rawAnsi, options.colors[8 + (code - 100)]);
    }

    return result;
}

function resetStyles(stack: string[]) {
    const stackClone = stack.slice(0);

    stack.length = 0;

    return stackClone.reverse().map(function (tag) {
        return '</' + tag + '>';
    }).join('');
}

/**
 * Creates an array of numbers ranging from low to high
 */
function range(low: number, high: number): number[] {
    const results: number[] = [];

    for (let j = low; j <= high; j++) {
        results.push(j);
    }

    return results;
}



/**
 * Returns a new function that is true if value is NOT the same category
 */
function notCategory(category: string | null) {
    return function (e: StickyStackType) {
        return (category === null || e.category !== category) && category !== 'all';
    };
}

/**
 * Converts a code into an ansi token type
 */
function categoryForCode(code: number): string | null {
    code = parseInt(String(code), 10);
    let result = null;

    if (code === 0) {
        result = 'all';
    } else if (code === 1) {
        result = 'bold';
    } else if ((2 < code && code < 5)) {
        result = 'underline';
    } else if ((4 < code && code < 7)) {
        result = 'blink';
    } else if (code === 8) {
        result = 'hide';
    } else if (code === 9) {
        result = 'strike';
    } else if ((29 < code && code < 38) || code === 39 || (89 < code && code < 98)) {
        result = 'foreground-color';
    } else if ((39 < code && code < 48) || code === 49 || (99 < code && code < 108)) {
        result = 'background-color';
    }

    return result;
}

function pushText(text: string, options: Options): string {
    if (options.escapeXML) {
        return entities.encodeXML(text);
    }

    return text;
}

function pushTag(stack: string[], rawAnsi: string, tag: string, style?: string): string {
    if (!style) { style = ''; }

    stack.push(tag);

    return `<${tag}${style ? ` style="${style}"` : ''} data-ansi="${rawAnsi}">`;
}

function pushStyle(stack: string[], rawAnsi: string, style: string): string {
    return pushTag(stack, rawAnsi, 'span', style);
}

function pushForegroundColor(stack: string[], rawAnsi: string, color: string) {
    return pushTag(stack, rawAnsi, 'span', 'color:' + color);
}

function pushBackgroundColor(stack: string[], rawAnsi: string, color: string) {
    return pushTag(stack, rawAnsi, 'span', 'background-color:' + color);
}

function closeTag(stack: string[], style: string) {
    let last;

    if (stack.slice(-1)[0] === style) {
        last = stack.pop();
    }

    if (last) {
        return '</' + style + '>';
    }
}

function tokenize(text: string, options: Options, callback: Callback): number[] {
    let ansiMatch = false;
    const ansiHandler = 3;

    function remove() {
        return '';
    }

    function removeXterm256Foreground(_: string, g1: string) {
        callback('xterm256Foreground', g1);
        return '';
    }

    function removeXterm256Background(_: string, g1: string) {
        callback('xterm256Background', g1);
        return '';
    }

    function newline(m: string) {
        if (options.newline) {
            callback('display', '-1');
        } else {
            callback('text', m);
        }

        return '';
    }

    function ansiMess(_: string, g1: string) {
        ansiMatch = true;
        if (g1.trim().length === 0) {
            g1 = '0';
        }

        let rawAnsi = g1.replace(/;$/, '');
        let ga = rawAnsi.split(';');

        for (const g of ga) {
            callback('display', g, rawAnsi);
        }

        return '';
    }

    function realText(m: string) {
        callback('text', m);

        return '';
    }

    function rgb(m: string) {
        callback('rgb', m);

        return '';
    }

    /* eslint no-control-regex:0 */
    const tokens: Handler[] = [{
        pattern: /^\x08+/,
        sub: remove
    }, {
        pattern: /^\x1b\[[012]?K/,
        sub: remove
    }, {
        pattern: /^\x1b\[\(B/,
        sub: remove
    }, {
        pattern: /^\x1b\[[34]8;2;\d+;\d+;\d+m/,
        sub: rgb
    }, {
        pattern: /^\x1b\[38;5;(\d+)m/,
        sub: removeXterm256Foreground
    }, {
        pattern: /^\x1b\[48;5;(\d+)m/,
        sub: removeXterm256Background
    }, {
        pattern: /^\n/,
        sub: newline
    }, {
        pattern: /^\r+\n/,
        sub: newline
    }, {
        pattern: /^\r/,
        sub: newline
    }, {
        pattern: /^\x1b\[((?:\d{1,3};?)+|)m/,
        sub: ansiMess
    }, {
        // CSI n J
        // ED - Erase in Display Clears part of the screen.
        // If n is 0 (or missing), clear from cursor to end of screen.
        // If n is 1, clear from cursor to beginning of the screen.
        // If n is 2, clear entire screen (and moves cursor to upper left on DOS ANSI.SYS).
        // If n is 3, clear entire screen and delete all lines saved in the scrollback buffer
        //   (this feature was added for xterm and is supported by other terminal applications).
        pattern: /^\x1b\[\d?J/,
        sub: remove
    }, {
        // CSI n ; m f
        // HVP - Horizontal Vertical Position Same as CUP
        pattern: /^\x1b\[\d{0,3};\d{0,3}f/,
        sub: remove
    }, {
        // catch-all for CSI sequences?
        pattern: /^\x1b\[?[\d;]{0,3}/,
        sub: remove
    }, {
        /**
         * extracts real text - not containing:
         * - `\x1b' - ESC - escape (Ascii 27)
         * - '\x08' - BS - backspace (Ascii 8)
         * - `\n` - Newline - linefeed (LF) (ascii 10)
         * - `\r` - Windows Carriage Return (CR)
         */
        pattern: /^(([^\x1b\x08\r\n])+)/,
        sub: realText
    }];

    function process(handler: Handler, i: number) {
        if (i > ansiHandler && ansiMatch) {
            return;
        }

        ansiMatch = false;

        text = text.replace(handler.pattern, handler.sub);
    }

    const results1: number[] = [];
    let { length } = text;

    outer:
    while (length > 0) {
        for (let i = 0, o = 0, len = tokens.length; o < len; i = ++o) {
            const handler: Handler = tokens[i];
            process(handler, i);

            if (text.length !== length) {
                // We matched a token and removed it from the text. We need to
                // start matching *all* tokens against the new text.
                length = text.length;
                continue outer;
            }
        }

        if (text.length === length) {
            break;
        }
        results1.push(0);

        length = text.length;
    }

    return results1;
}

/**
 * If streaming, then the stack is "sticky"
 */
function updateStickyStack(stickyStack: StickyStackType[], token: string, data: string): StickyStackType[] {
    if (token !== 'text') {
        stickyStack = stickyStack.filter(notCategory(categoryForCode(Number(data))));
        stickyStack.push({ token, data, category: categoryForCode(Number(data)) });
    }

    return stickyStack;
}

export default class Filter {
    options: Options;
    stack: string[];
    stickyStack: StickyStackType[];
    constructor(options: Partial<Options>) {
        options = options || {};

        if (options.colors) {
            options.colors = Object.assign({}, defaultOpts.colors, options.colors);
        }

        this.options = Object.assign({}, defaultOpts, options);
        this.stack = [];
        this.stickyStack = [];
    }
    toHtml(input: string | string[]): string {
        input = typeof input === 'string' ? [input] : input;
        const { stack, options } = this;
        const buf: CodeLike[] = [];

        this.stickyStack.forEach(element => {
            const output = generateOutput(stack, element.token, element.data, '', options);

            if (output) {
                buf.push(output);
            }
        });

        tokenize(input.join(''), options, (token: string, data: string, rawAnsi: string = '') => {
            const output = generateOutput(stack, token, data, rawAnsi, options);

            if (output) {
                buf.push(output);
            }

            if (options.stream) {
                this.stickyStack = updateStickyStack(this.stickyStack, token, data);
            }
        });

        if (stack.length) {
            buf.push(resetStyles(stack));
        }

        return buf.join('');
    }
    toAnsi(html: string): string {
        const dom = document.createElement('div');
        dom.innerHTML = html;
        const buf = []
        for (let i = 0; i < dom.children.length; i++) {
            const child = dom.children[i];
            let ansi = child.getAttribute('data-ansi') || '0';
            if (ansi !== '0') {
                buf.push(`\x1b[${ansi}m${child.textContent}\x1b[0m`);
            } else {
                buf.push(child.textContent);
            }
        }
        return buf.join('');
    }
}