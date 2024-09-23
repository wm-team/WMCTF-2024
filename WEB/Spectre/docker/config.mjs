const asBool = (v) => {
    if (typeof v === "undefined") return false;
    if (typeof v === "boolean") return Boolean(v);
    if (typeof v === "number") return v !== 0;
    if (typeof v === "string") {
        if (v === "true") return true;
        if (v === "false") return false;
        if (/^ *$/.test(v)) return false;
        if (/^\d+$/.test(v)) return parseInt(v) !== 0;
        return true
    }
    if (v === null) return false;
    return true
}

function randomTokenKey(len) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const key = Array.from({ length: len }, () => alphabet[Math.floor(Math.random() * alphabet.length)]).join("");
    console.log("Generated token key:", key);
    return key;
}

export default {
    "main_port": 3000,
    "assets_port": 3001,
    // "token_key": process.env["TOKEN_KEY"] || "h1LxPW90aJehe6sV",
    "token_key": process.env["TOKEN_KEY"] || randomTokenKey(16),
    "placeholder_code_default": "<!-- Write your code here -->",
    "placeholder_code_404": "<!-- This is not what you are looking for -->",
    "default_role": "user",
    "bot_visit_timeout": 30 * 1000,
    "generate_default_account": (process.env["NODE_ENV"].trim() === "development") ? true : false,
    "cf_turnstile": {
        "enable": asBool(process.env["ENABLE_CF_TURNSTILE"]),
        "site_key": process.env["CF_TURNSTILE_SITE_KEY"],
        "secret_key": process.env["CF_TURNSTILE_SECRET_KEY"]
    }
}
