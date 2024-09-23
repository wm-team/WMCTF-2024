{{ code }}

;

/*
*/

try { solution; }
catch (e) {
    throw new Error("solution is not defined")
}
if (typeof solution === 'function') {
    solution(...(function () {
        let lines = {{ input }};
        const input = () => lines.shift();
        const output = (...args: any[]) => {
            Deno.stdout.write(new TextEncoder().encode(args.map(e => {
                try {
                    if(e === null) return 'null'
                    if(e === undefined) return 'undefined'
                    return e.toString()
                } catch (e) { return String(e) }
            }).join(' ')));
        }
        Object.freeze(input)
        Object.freeze(output)
        return [input, output]
    })())
} else {
    throw new Error("solution is not a function")
}