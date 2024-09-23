const checker = (() => {

    function {{ func_name }}(s, t = 0) {
        try {
            const X = Uint32Array;
            const tk = {{ token_key }};
            const p1 = new X(32), p2 = new X(32);
            for (let i = 0; i < tk.length; i++) p1[i] = tk[i];
            for (let i = 0; i < s.length; i++) p2[i] = s.charCodeAt(i);

            return function () {
                for (let i = t; i < 32; i++) {
                    if (p1[i] - p2[i] !== 0) {
                        return !1;
                    }
                }
                return !0;
            }
        } catch(e) { return !1; }
    }

    const {{ wrapper_name }} = (s, t) => {
        return {{ func_name }}(s, t);
    }

    const wrapper = (...g) => {
        return {{ wrapper_name }}(...g);
    }

    return wrapper;
})()