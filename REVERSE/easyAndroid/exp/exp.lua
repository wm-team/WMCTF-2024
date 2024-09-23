jit.off()
local bit = require("bit")

function AAA(key, data)
    local S = {}
    for i = 1, 256 do
        S[i] = i - 1
    end
    local j = 0
    for i = 1, 256 do
        j = (j + S[i] + string.byte(key, i % #key + 1)) % 256
        S[i], S[j+1] = S[j+1], S[i]
    end
    local i, j = 1, 0
    local result = ''
    local printHex = ''
    for byte in (data:gmatch "." ) do
        i = (i + 1) % 256
        j = (j + S[i+1]) % 256
        S[i+1], S[j+1] = S[j+1], S[i+1]
        local t = (S[i+1] + S[j+1]) % 256
        local k = S[t+1]
        local xorResult = bit.bxor(string.byte(byte), k)
        local hexString = string.format("%02x", xorResult)
        printHex = printHex .. hexString
        result = result .. string.char(xorResult)
    end
    print("flag: " .. result)
    return printHex
end

local data = {0x9e, 0x51, 0x12, 0xe8, 0xca, 0x6d, 0x17, 0x00, 0x27, 0x12, 0x80, 0x76, 0x3d, 0xf5, 0x44, 0x92, 0x7f, 0x77, 0x6a, 0xee, 0xd3, 0xf0, 0xe8, 0xab, 0xd1, 0x6f, 0x51, 0x0c, 0x79, 0xdd, 0x62, 0xbe, 0xd1, 0xfe, 0x11, 0xbc,}
local res = ''
for i = 1, #data do
    res = res .. string.char(data[i])
end
AAA("e2bee3ede3e3e2bfe3b9bfe2bfbbbfe2bfbf", res)