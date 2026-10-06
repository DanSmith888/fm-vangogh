// PBKDF2-HMAC-SHA1 for EAR key derivation, one candidate per invocation.
// Derives the 32-byte AES-256 key: PBKDF2-HMAC-SHA1(password UTF-16LE, salt, n_iter).
// The host does the AES trial-decrypt and the correctness check on the keys we return.

struct Params {
    salt0: u32, salt1: u32, salt2: u32, salt3: u32,
    n_iter: u32,
    count: u32,
    _pad0: u32, _pad1: u32,
};

@group(0) @binding(0) var<uniform> P: Params;
@group(0) @binding(1) var<storage, read> pw: array<u32>;    // 16 u32 (64 bytes) per candidate
@group(0) @binding(2) var<storage, read> lens: array<u32>;  // password byte length per candidate
@group(0) @binding(3) var<storage, read_write> outk: array<u32>; // 8 u32 (32 bytes) per candidate

fn rotl(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }
fn bswap(x: u32) -> u32 {
    return ((x & 0xffu) << 24u) | ((x & 0xff00u) << 8u) | ((x & 0xff0000u) >> 8u) | ((x >> 24u) & 0xffu);
}

// Fully unrolled, register-resident SHA1 (generated). 16 rolling word vars,
// no dynamic array indexing and no per-round branches.
fn sha1_transform(st: array<u32,5>, win: array<u32,16>) -> array<u32,5> {
    var w0 = win[0u];
    var w1 = win[1u];
    var w2 = win[2u];
    var w3 = win[3u];
    var w4 = win[4u];
    var w5 = win[5u];
    var w6 = win[6u];
    var w7 = win[7u];
    var w8 = win[8u];
    var w9 = win[9u];
    var w10 = win[10u];
    var w11 = win[11u];
    var w12 = win[12u];
    var w13 = win[13u];
    var w14 = win[14u];
    var w15 = win[15u];
    var a = st[0]; var b = st[1]; var c = st[2]; var d = st[3]; var e = st[4];
    let t0 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w0;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t0;
    let t1 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w1;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t1;
    let t2 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w2;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t2;
    let t3 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w3;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t3;
    let t4 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w4;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t4;
    let t5 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w5;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t5;
    let t6 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w6;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t6;
    let t7 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w7;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t7;
    let t8 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w8;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t8;
    let t9 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w9;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t9;
    let t10 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w10;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t10;
    let t11 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w11;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t11;
    let t12 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w12;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t12;
    let t13 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w13;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t13;
    let t14 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w14;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t14;
    let t15 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w15;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t15;
    w0 = rotl(w13 ^ w8 ^ w2 ^ w0, 1u);
    let t16 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w0;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t16;
    w1 = rotl(w14 ^ w9 ^ w3 ^ w1, 1u);
    let t17 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w1;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t17;
    w2 = rotl(w15 ^ w10 ^ w4 ^ w2, 1u);
    let t18 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w2;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t18;
    w3 = rotl(w0 ^ w11 ^ w5 ^ w3, 1u);
    let t19 = rotl(a, 5u) + ((b & c) | ((~b) & d)) + e + 0x5A827999u + w3;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t19;
    w4 = rotl(w1 ^ w12 ^ w6 ^ w4, 1u);
    let t20 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w4;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t20;
    w5 = rotl(w2 ^ w13 ^ w7 ^ w5, 1u);
    let t21 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w5;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t21;
    w6 = rotl(w3 ^ w14 ^ w8 ^ w6, 1u);
    let t22 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w6;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t22;
    w7 = rotl(w4 ^ w15 ^ w9 ^ w7, 1u);
    let t23 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w7;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t23;
    w8 = rotl(w5 ^ w0 ^ w10 ^ w8, 1u);
    let t24 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w8;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t24;
    w9 = rotl(w6 ^ w1 ^ w11 ^ w9, 1u);
    let t25 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w9;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t25;
    w10 = rotl(w7 ^ w2 ^ w12 ^ w10, 1u);
    let t26 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w10;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t26;
    w11 = rotl(w8 ^ w3 ^ w13 ^ w11, 1u);
    let t27 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w11;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t27;
    w12 = rotl(w9 ^ w4 ^ w14 ^ w12, 1u);
    let t28 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w12;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t28;
    w13 = rotl(w10 ^ w5 ^ w15 ^ w13, 1u);
    let t29 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w13;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t29;
    w14 = rotl(w11 ^ w6 ^ w0 ^ w14, 1u);
    let t30 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w14;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t30;
    w15 = rotl(w12 ^ w7 ^ w1 ^ w15, 1u);
    let t31 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w15;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t31;
    w0 = rotl(w13 ^ w8 ^ w2 ^ w0, 1u);
    let t32 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w0;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t32;
    w1 = rotl(w14 ^ w9 ^ w3 ^ w1, 1u);
    let t33 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w1;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t33;
    w2 = rotl(w15 ^ w10 ^ w4 ^ w2, 1u);
    let t34 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w2;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t34;
    w3 = rotl(w0 ^ w11 ^ w5 ^ w3, 1u);
    let t35 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w3;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t35;
    w4 = rotl(w1 ^ w12 ^ w6 ^ w4, 1u);
    let t36 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w4;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t36;
    w5 = rotl(w2 ^ w13 ^ w7 ^ w5, 1u);
    let t37 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w5;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t37;
    w6 = rotl(w3 ^ w14 ^ w8 ^ w6, 1u);
    let t38 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w6;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t38;
    w7 = rotl(w4 ^ w15 ^ w9 ^ w7, 1u);
    let t39 = rotl(a, 5u) + (b ^ c ^ d) + e + 0x6ED9EBA1u + w7;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t39;
    w8 = rotl(w5 ^ w0 ^ w10 ^ w8, 1u);
    let t40 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w8;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t40;
    w9 = rotl(w6 ^ w1 ^ w11 ^ w9, 1u);
    let t41 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w9;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t41;
    w10 = rotl(w7 ^ w2 ^ w12 ^ w10, 1u);
    let t42 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w10;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t42;
    w11 = rotl(w8 ^ w3 ^ w13 ^ w11, 1u);
    let t43 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w11;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t43;
    w12 = rotl(w9 ^ w4 ^ w14 ^ w12, 1u);
    let t44 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w12;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t44;
    w13 = rotl(w10 ^ w5 ^ w15 ^ w13, 1u);
    let t45 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w13;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t45;
    w14 = rotl(w11 ^ w6 ^ w0 ^ w14, 1u);
    let t46 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w14;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t46;
    w15 = rotl(w12 ^ w7 ^ w1 ^ w15, 1u);
    let t47 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w15;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t47;
    w0 = rotl(w13 ^ w8 ^ w2 ^ w0, 1u);
    let t48 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w0;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t48;
    w1 = rotl(w14 ^ w9 ^ w3 ^ w1, 1u);
    let t49 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w1;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t49;
    w2 = rotl(w15 ^ w10 ^ w4 ^ w2, 1u);
    let t50 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w2;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t50;
    w3 = rotl(w0 ^ w11 ^ w5 ^ w3, 1u);
    let t51 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w3;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t51;
    w4 = rotl(w1 ^ w12 ^ w6 ^ w4, 1u);
    let t52 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w4;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t52;
    w5 = rotl(w2 ^ w13 ^ w7 ^ w5, 1u);
    let t53 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w5;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t53;
    w6 = rotl(w3 ^ w14 ^ w8 ^ w6, 1u);
    let t54 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w6;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t54;
    w7 = rotl(w4 ^ w15 ^ w9 ^ w7, 1u);
    let t55 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w7;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t55;
    w8 = rotl(w5 ^ w0 ^ w10 ^ w8, 1u);
    let t56 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w8;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t56;
    w9 = rotl(w6 ^ w1 ^ w11 ^ w9, 1u);
    let t57 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w9;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t57;
    w10 = rotl(w7 ^ w2 ^ w12 ^ w10, 1u);
    let t58 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w10;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t58;
    w11 = rotl(w8 ^ w3 ^ w13 ^ w11, 1u);
    let t59 = rotl(a, 5u) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDCu + w11;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t59;
    w12 = rotl(w9 ^ w4 ^ w14 ^ w12, 1u);
    let t60 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w12;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t60;
    w13 = rotl(w10 ^ w5 ^ w15 ^ w13, 1u);
    let t61 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w13;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t61;
    w14 = rotl(w11 ^ w6 ^ w0 ^ w14, 1u);
    let t62 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w14;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t62;
    w15 = rotl(w12 ^ w7 ^ w1 ^ w15, 1u);
    let t63 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w15;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t63;
    w0 = rotl(w13 ^ w8 ^ w2 ^ w0, 1u);
    let t64 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w0;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t64;
    w1 = rotl(w14 ^ w9 ^ w3 ^ w1, 1u);
    let t65 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w1;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t65;
    w2 = rotl(w15 ^ w10 ^ w4 ^ w2, 1u);
    let t66 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w2;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t66;
    w3 = rotl(w0 ^ w11 ^ w5 ^ w3, 1u);
    let t67 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w3;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t67;
    w4 = rotl(w1 ^ w12 ^ w6 ^ w4, 1u);
    let t68 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w4;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t68;
    w5 = rotl(w2 ^ w13 ^ w7 ^ w5, 1u);
    let t69 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w5;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t69;
    w6 = rotl(w3 ^ w14 ^ w8 ^ w6, 1u);
    let t70 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w6;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t70;
    w7 = rotl(w4 ^ w15 ^ w9 ^ w7, 1u);
    let t71 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w7;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t71;
    w8 = rotl(w5 ^ w0 ^ w10 ^ w8, 1u);
    let t72 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w8;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t72;
    w9 = rotl(w6 ^ w1 ^ w11 ^ w9, 1u);
    let t73 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w9;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t73;
    w10 = rotl(w7 ^ w2 ^ w12 ^ w10, 1u);
    let t74 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w10;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t74;
    w11 = rotl(w8 ^ w3 ^ w13 ^ w11, 1u);
    let t75 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w11;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t75;
    w12 = rotl(w9 ^ w4 ^ w14 ^ w12, 1u);
    let t76 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w12;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t76;
    w13 = rotl(w10 ^ w5 ^ w15 ^ w13, 1u);
    let t77 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w13;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t77;
    w14 = rotl(w11 ^ w6 ^ w0 ^ w14, 1u);
    let t78 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w14;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t78;
    w15 = rotl(w12 ^ w7 ^ w1 ^ w15, 1u);
    let t79 = rotl(a, 5u) + (b ^ c ^ d) + e + 0xCA62C1D6u + w15;
    e = d; d = c; c = rotl(b, 30u); b = a; a = t79;
    return array<u32,5>(st[0]+a, st[1]+b, st[2]+c, st[3]+d, st[4]+e);
}

fn init_state() -> array<u32,5> {
    return array<u32,5>(0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u);
}

fn getbyte(cand: u32, j: u32) -> u32 {
    return (pw[cand * 16u + (j >> 2u)] >> (8u * (j & 3u))) & 0xffu;
}

fn salt_byte(j: u32) -> u32 {
    var word: u32;
    if (j < 4u) { word = P.salt0; } else if (j < 8u) { word = P.salt1; }
    else if (j < 12u) { word = P.salt2; } else { word = P.salt3; }
    return (word >> (8u * (j & 3u))) & 0xffu;
}

// Build the 64-byte HMAC key pad block (big-endian words), key XOR pad.
fn pad_block(cand: u32, len: u32, pad: u32) -> array<u32,16> {
    var blk: array<u32,16>;
    for (var mw = 0u; mw < 16u; mw++) {
        var w = 0u;
        for (var t = 0u; t < 4u; t++) {
            let j = mw * 4u + t;
            var kb = 0u;
            if (j < len) { kb = getbyte(cand, j); }
            w = (w << 8u) | (kb ^ pad);
        }
        blk[mw] = w;
    }
    return blk;
}

// HMAC-SHA1 over a 20-byte message, using precomputed inner/outer states.
fn hmac20(istate: array<u32,5>, ostate: array<u32,5>, msg: array<u32,5>) -> array<u32,5> {
    var w: array<u32,16>;
    for (var i = 0u; i < 5u; i++) { w[i] = msg[i]; }
    w[5] = 0x80000000u;
    for (var i = 6u; i < 15u; i++) { w[i] = 0u; }
    w[15] = 672u;                       // (64 + 20) * 8 bits
    let inner = sha1_transform(istate, w);

    var w2: array<u32,16>;
    for (var i = 0u; i < 5u; i++) { w2[i] = inner[i]; }
    w2[5] = 0x80000000u;
    for (var i = 6u; i < 15u; i++) { w2[i] = 0u; }
    w2[15] = 672u;
    return sha1_transform(ostate, w2);
}

fn pbkdf2_block(istate: array<u32,5>, ostate: array<u32,5>, idx: u32) -> array<u32,5> {
    var msg: array<u32,5>;
    msg[0] = (salt_byte(0u) << 24u) | (salt_byte(1u) << 16u) | (salt_byte(2u) << 8u) | salt_byte(3u);
    msg[1] = (salt_byte(4u) << 24u) | (salt_byte(5u) << 16u) | (salt_byte(6u) << 8u) | salt_byte(7u);
    msg[2] = (salt_byte(8u) << 24u) | (salt_byte(9u) << 16u) | (salt_byte(10u) << 8u) | salt_byte(11u);
    msg[3] = (salt_byte(12u) << 24u) | (salt_byte(13u) << 16u) | (salt_byte(14u) << 8u) | salt_byte(15u);
    msg[4] = idx;                        // INT32BE(block index)

    var u = hmac20(istate, ostate, msg);
    var t = u;
    for (var c = 1u; c < P.n_iter; c++) {
        u = hmac20(istate, ostate, u);
        for (var i = 0u; i < 5u; i++) { t[i] = t[i] ^ u[i]; }
    }
    return t;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
    let cand = gid.x;
    if (cand >= P.count) { return; }
    let len = lens[cand];

    let istate = sha1_transform(init_state(), pad_block(cand, len, 0x36u));
    let ostate = sha1_transform(init_state(), pad_block(cand, len, 0x5cu));

    let t1 = pbkdf2_block(istate, ostate, 1u);  // key bytes 0..19
    let t2 = pbkdf2_block(istate, ostate, 2u);  // key bytes 20..31 (first 12)

    let base = cand * 8u;
    outk[base + 0u] = bswap(t1[0]);
    outk[base + 1u] = bswap(t1[1]);
    outk[base + 2u] = bswap(t1[2]);
    outk[base + 3u] = bswap(t1[3]);
    outk[base + 4u] = bswap(t1[4]);
    outk[base + 5u] = bswap(t2[0]);
    outk[base + 6u] = bswap(t2[1]);
    outk[base + 7u] = bswap(t2[2]);
}
