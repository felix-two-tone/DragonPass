'use strict';

(() => {
  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => [...root.querySelectorAll(s)];
  const log2 = Math.log2;
  const clamp = (n, lo, hi) => Math.min(hi, Math.max(lo, Number.isFinite(n) ? n : lo));

  class GenError extends Error {}

  // ---------------------------------------------------------------------------
  // Cryptographically secure randomness (rejection sampling, no modulo bias)
  // ---------------------------------------------------------------------------
  const rand = {
    int(n) {
      if (n <= 1) return 0;
      const limit = Math.floor(0x100000000 / n) * n;
      const buf = new Uint32Array(1);
      let x;
      do {
        crypto.getRandomValues(buf);
        x = buf[0];
      } while (x >= limit);
      return x % n;
    },
    pick(arr) { return arr[this.int(arr.length)]; },
    bool() { return this.int(2) === 1; },
    shuffle(arr) {
      for (let i = arr.length - 1; i > 0; i--) {
        const j = this.int(i + 1);
        [arr[i], arr[j]] = [arr[j], arr[i]];
      }
      return arr;
    },
    bytes(n) {
      const b = new Uint8Array(n);
      crypto.getRandomValues(b);
      return b;
    },
  };

  // ---------------------------------------------------------------------------
  // Character sets
  // ---------------------------------------------------------------------------
  const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const LOWER = 'abcdefghijklmnopqrstuvwxyz';
  const DIGITS = '0123456789';
  const SIMILAR = 'il1Lo0OI|';
  const AMBIGUOUS = '{}[]()/\\\'"`~,;:.<>';
  const ASCII_PRINTABLE = Array.from({ length: 94 }, (_, i) => String.fromCharCode(33 + i)).join('');

  // cat: which "minimum count" bucket a set feeds
  const CHARSETS = [
    { key: 'upper', cat: 'upper', chars: UPPER },
    { key: 'lower', cat: 'lower', chars: LOWER },
    { key: 'digits', cat: 'digit', chars: DIGITS },
    { key: 'symbols', cat: 'special', chars: null }, // user-editable
    { key: 'punct', cat: 'special', chars: '.,:;?' },
    { key: 'brackets', cat: 'special', chars: '()[]{}<>' },
    { key: 'math', cat: 'special', chars: '+-=~' },
    { key: 'quotes', cat: 'special', chars: '\'"`' },
    { key: 'slashes', cat: 'special', chars: '\\/|_' },
    { key: 'space', cat: 'special', chars: ' ' },
    { key: 'latin', cat: 'special', chars: 'ÀÁÂÄÅÆÇÈÉÊËÌÍÎÏÑÒÓÔÖØÙÚÛÜÝàáâäåæçèéêëìíîïñòóôöøùúûüýÿß' },
    { key: 'greek', cat: 'special', chars: 'ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩαβγδεζηθικλμνξοπρστυφχψω' },
    { key: 'runes', cat: 'special', chars: 'ᚠᚢᚦᚨᚱᚲᚷᚹᚺᚾᛁᛃᛇᛈᛉᛊᛏᛒᛖᛗᛚᛜᛞᛟ' },
  ];
  const CAT_LABEL = { upper: 'uppercase letters', lower: 'lowercase letters', digit: 'digits', special: 'symbols' };

  const isLetter = ch => /\p{L}/u.test(ch);

  function charClass(ch) {
    if (ch >= 'A' && ch <= 'Z') return 'c-upper';
    if (ch >= 'a' && ch <= 'z') return 'c-lower';
    if (ch >= '0' && ch <= '9') return 'c-digit';
    if (ch === ' ') return 'c-space';
    if (ch.charCodeAt(0) < 128) return 'c-symbol';
    return 'c-other';
  }

  // Three consecutive code points of the same kind, ascending or descending (abc, 321, ZYX)
  function isRun(a, b, c) {
    const kind = ch => (/[a-z]/.test(ch) ? 1 : /[A-Z]/.test(ch) ? 2 : /[0-9]/.test(ch) ? 3 : 0);
    const k = kind(a);
    if (!k || kind(b) !== k || kind(c) !== k) return false;
    const d1 = b.charCodeAt(0) - a.charCodeAt(0);
    const d2 = c.charCodeAt(0) - b.charCodeAt(0);
    return d1 === d2 && Math.abs(d1) === 1;
  }

  const uniqueChars = str => [...new Set(Array.from(str || ''))];

  // ---------------------------------------------------------------------------
  // Generators. Each returns { value, bits, info? }.
  // ---------------------------------------------------------------------------

  function buildRandomClasses(o) {
    const exclude = new Set(Array.from(o.r_exclude || ''));
    if (o.r_noSimilar) for (const c of SIMILAR) exclude.add(c);
    if (o.r_noAmbiguous) for (const c of AMBIGUOUS) exclude.add(c);

    const seen = new Set();
    const classes = [];
    const add = (key, cat, str) => {
      const chars = [];
      for (const c of Array.from(str)) {
        if (exclude.has(c) || seen.has(c) || c === '\n' || c === '\t') continue;
        seen.add(c);
        chars.push(c);
      }
      if (chars.length) classes.push({ key, cat, chars });
    };
    for (const cs of CHARSETS) {
      if (o['r_' + cs.key]) add(cs.key, cs.cat, cs.chars ?? o.r_symbolChars ?? '');
    }
    if (o.r_useCustom && o.r_customChars) add('custom', 'special', o.r_customChars);
    return classes;
  }

  function genRandom(o) {
    const len = clamp(o.r_length, 4, 256);
    const classes = buildRandomClasses(o);
    if (!classes.length) throw new GenError('Choose at least one character set (and check your exclusions).');

    const pool = classes.flatMap(c => c.chars);
    const catOf = new Map();
    const catPool = { upper: [], lower: [], digit: [], special: [] };
    for (const c of classes) {
      catPool[c.cat].push(...c.chars);
      for (const ch of c.chars) catOf.set(ch, c.cat);
    }

    const mins = {
      upper: clamp(o.r_minUpper, 0, 256),
      lower: clamp(o.r_minLower, 0, 256),
      digit: clamp(o.r_minDigits, 0, 256),
      special: clamp(o.r_minSpecial, 0, 256),
    };
    const fromEach = { upper: 0, lower: 0, digit: 0, special: 0 };
    if (o.r_requireEach) for (const c of classes) fromEach[c.cat]++;

    let required = 0;
    for (const k in mins) {
      if (mins[k] > 0 && !catPool[k].length) {
        throw new GenError(`You asked for at least ${mins[k]} ${CAT_LABEL[k]}, but none are enabled.`);
      }
      if (o.r_noDup && mins[k] > catPool[k].length) {
        throw new GenError(`Only ${catPool[k].length} distinct ${CAT_LABEL[k]} are available — lower the minimum or allow repeats.`);
      }
      required += Math.max(mins[k], fromEach[k]);
    }
    if (required > len) throw new GenError(`Your rules need ${required} characters, but the length is ${len}.`);
    if (o.r_noDup && pool.length < len) {
      throw new GenError(`Only ${pool.length} distinct characters are available — shorten the password or allow repeats.`);
    }

    const startOk = ch => (!o.r_startLetter || isLetter(ch)) && (!o.r_noEdgeSpecial || catOf.get(ch) !== 'special');
    const endOk = ch => !o.r_noEdgeSpecial || catOf.get(ch) !== 'special';
    if (!pool.some(startOk)) throw new GenError('No enabled character can start the password under your rules.');

    // Move a qualifying character into position idx by swapping (keeps the multiset intact)
    const fix = (out, idx, ok, avoid) => {
      if (ok(out[idx])) return true;
      const cands = [];
      out.forEach((ch, j) => { if (j !== idx && j !== avoid && ok(ch)) cands.push(j); });
      if (!cands.length) return false;
      const j = rand.pick(cands);
      [out[idx], out[j]] = [out[j], out[idx]];
      return true;
    };

    const valid = out => {
      for (let i = 1; i < out.length; i++) {
        if (o.r_noConsec && out[i] === out[i - 1]) return false;
        if (o.r_noSeq && i >= 2 && isRun(out[i - 2], out[i - 1], out[i])) return false;
      }
      return true;
    };

    for (let attempt = 0; attempt < 3000; attempt++) {
      const used = new Set();
      const out = [];
      const take = arr => {
        const avail = o.r_noDup ? arr.filter(c => !used.has(c)) : arr;
        if (!avail.length) return false;
        const c = rand.pick(avail);
        used.add(c);
        out.push(c);
        return true;
      };

      const counts = { upper: 0, lower: 0, digit: 0, special: 0 };
      let ok = true;
      if (o.r_requireEach) {
        for (const c of classes) {
          if (!take(c.chars)) { ok = false; break; }
          counts[c.cat]++;
        }
      }
      for (const k in mins) {
        while (ok && counts[k] < mins[k]) {
          if (!take(catPool[k])) ok = false;
          counts[k]++;
        }
      }
      while (ok && out.length < len) if (!take(pool)) ok = false;
      if (!ok) continue;

      rand.shuffle(out);
      if (!fix(out, 0, startOk, -1)) continue;
      if (!fix(out, out.length - 1, endOk, 0)) continue;
      if (!valid(out)) continue;

      let bits = 0;
      for (let i = 0; i < len; i++) bits += log2(o.r_noDup ? pool.length - i : pool.length);
      return {
        value: out.join(''),
        bits,
        info: `Pool of ${pool.length} characters · ${log2(pool.length).toFixed(2)} bits each`,
      };
    }
    throw new GenError('Couldn’t satisfy every rule at once — try loosening a few of them.');
  }

  const LEET = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7', A: '4', E: '3', I: '1', O: '0', S: '5', T: '7' };

  function genPassphrase(o) {
    const minLen = clamp(o.p_minLen, 1, 30);
    const maxLen = clamp(o.p_maxLen, minLen, 30);
    const list = (window.DP_WORDS[o.p_list] || window.DP_WORDS.both).filter(w => w.length >= minLen && w.length <= maxLen);
    const n = clamp(o.p_words, 2, 20);
    if (list.length < 2) throw new GenError('No words match that length range — widen it.');
    if (o.p_unique && list.length < n) throw new GenError(`Only ${list.length} words fit those lengths — widen the range or allow repeats.`);

    let bits = 0;
    const avail = [...list];
    let words = [];
    for (let i = 0; i < n; i++) {
      const idx = rand.int(avail.length);
      bits += log2(avail.length);
      words.push(avail[idx]);
      if (o.p_unique) avail.splice(idx, 1);
    }

    const title = w => w[0].toUpperCase() + w.slice(1);
    switch (o.p_case) {
      case 'title': words = words.map(title); break;
      case 'upper': words = words.map(w => w.toUpperCase()); break;
      case 'camel': words = words.map((w, i) => (i ? title(w) : w)); break;
      case 'alternate': words = words.map((w, i) => (i % 2 ? w.toUpperCase() : w)); break;
      case 'randomWord':
        words = words.map(w => [w, title(w), w.toUpperCase()][rand.int(3)]);
        bits += n * log2(3);
        break;
      case 'randomLetter':
        words = words.map(w => {
          bits += w.length;
          return Array.from(w, c => (rand.bool() ? c.toUpperCase() : c)).join('');
        });
        break;
    }
    if (o.p_leet) words = words.map(w => Array.from(w, c => LEET[c] ?? c).join(''));

    const digitsN = clamp(o.p_digits, 1, 8);
    const digits = () => Array.from({ length: digitsN }, () => DIGITS[rand.int(10)]).join('');
    const digitBits = digitsN * log2(10);
    switch (o.p_number) {
      case 'end': words[n - 1] += digits(); bits += digitBits; break;
      case 'start': words[0] = digits() + words[0]; bits += digitBits; break;
      case 'random': words[rand.int(n)] += digits(); bits += digitBits + log2(n); break;
      case 'each': words = words.map(w => w + digits()); bits += n * digitBits; break;
    }

    const symPool = uniqueChars(o.p_symbolChars || '!');
    let sepFn;
    switch (o.p_sep) {
      case '@digit': sepFn = () => DIGITS[rand.int(10)]; bits += (n - 1) * log2(10); break;
      case '@symbol': sepFn = () => rand.pick(symPool); bits += (n - 1) * log2(symPool.length); break;
      case '@mixed': {
        const mix = [...DIGITS, ...symPool];
        sepFn = () => rand.pick(mix);
        bits += (n - 1) * log2(new Set(mix).size);
        break;
      }
      case '@custom': sepFn = () => o.p_sepCustom ?? ''; break;
      default: sepFn = () => o.p_sep;
    }
    let value = words.reduce((acc, w, i) => (i ? acc + sepFn() + w : w), '');

    const symBits = log2(symPool.length);
    if (o.p_symbol === 'end' || o.p_symbol === 'both') { value += rand.pick(symPool); bits += symBits; }
    if (o.p_symbol === 'start' || o.p_symbol === 'both') { value = rand.pick(symPool) + value; bits += symBits; }

    return {
      value,
      bits,
      info: `${list.length.toLocaleString()} words to choose from · ${log2(list.length).toFixed(2)} bits per word`,
    };
  }

  // Cluster onsets only follow an open syllable, so we never get "xsk"-style pile-ups.
  const SIMPLE_ONSETS = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'w', 'z'];
  const ONSETS = [...SIMPLE_ONSETS, 'br', 'dr', 'fr', 'gr', 'kr', 'pr', 'tr', 'th', 'sh', 'ch', 'st', 'sk', 'sl', 'sp', 'gl', 'fl', 'bl', 'vr'];
  const NUCLEI = ['a', 'e', 'i', 'o', 'u', 'ae', 'ai', 'au', 'ea', 'ei', 'ia', 'io', 'ou'];
  const CODAS = ['', 'n', 'r', 's', 'l', 'k', 'm', 'th', 'nd', 'rn', 'x'];

  function scatter(base, extras, place) {
    if (place === 'start') return { value: extras.join('') + base, bits: 0 };
    if (place === 'end') return { value: base + extras.join(''), bits: 0 };
    const chars = Array.from(base);
    let bits = 0;
    for (const e of extras) {
      const pos = rand.int(chars.length + 1);
      bits += log2(chars.length + 1);
      chars.splice(pos, 0, e);
    }
    return { value: chars.join(''), bits };
  }

  function genPronounceable(o) {
    const len = clamp(o.g_length, 6, 64);
    let s = '';
    let bits = 0;
    const starts = [];
    let coda = '';
    while (s.length < len) {
      starts.push(s.length);
      const onsets = coda ? SIMPLE_ONSETS : ONSETS;
      coda = rand.pick(CODAS);
      s += rand.pick(onsets) + rand.pick(NUCLEI) + coda;
      bits += log2(onsets.length) + log2(NUCLEI.length) + log2(CODAS.length);
    }
    // Different syllable sequences can spell the same string, so discount generously.
    bits = (bits * len) / s.length * 0.8;
    s = s.slice(0, len);

    let chars = Array.from(s);
    if (o.g_case === 'first') chars[0] = chars[0].toUpperCase();
    else if (o.g_case === 'syllable') starts.forEach(i => { if (i < len) chars[i] = chars[i].toUpperCase(); });
    else if (o.g_case === 'random') { chars = chars.map(c => (rand.bool() ? c.toUpperCase() : c)); bits += len; }

    const symPool = uniqueChars(o.g_symbolChars || '!');
    const nd = clamp(o.g_digits, 0, 8);
    const ns = clamp(o.g_symbols, 0, 6);
    const extras = [];
    for (let i = 0; i < nd; i++) { extras.push(DIGITS[rand.int(10)]); bits += log2(10); }
    for (let i = 0; i < ns; i++) { extras.push(rand.pick(symPool)); bits += log2(symPool.length); }
    rand.shuffle(extras);
    if (nd && ns) bits += log2(nd + ns); // ordering of digits vs symbols, roughly
    const placed = scatter(chars.join(''), extras, o.g_place);

    return {
      value: placed.value,
      bits: bits + placed.bits,
      info: `${len} letters + ${nd + ns} extras · strength is estimated conservatively`,
    };
  }

  const CONSONANTS = 'bcdfghjklmnpqrstvwxz';
  const PATTERN_TOKENS = {
    L: UPPER, l: LOWER, a: UPPER + LOWER, A: UPPER + LOWER + DIGITS, U: UPPER + DIGITS,
    C: CONSONANTS.toUpperCase(), c: CONSONANTS, V: 'AEIOU', v: 'aeiou',
    d: DIGITS, h: '0123456789abcdef', H: '0123456789ABCDEF',
    s: '!@#$%^&*?-_+=', '*': ASCII_PRINTABLE,
  };

  function parsePattern(p) {
    const parts = [];
    const src = Array.from(p);
    for (let i = 0; i < src.length; i++) {
      const ch = src[i];
      if (ch === '\\') {
        if (i + 1 < src.length) parts.push({ lit: src[++i] });
      } else if (ch === '[') {
        const end = src.indexOf(']', i + 1);
        if (end === -1) throw new GenError('Unclosed [ in pattern.');
        const set = uniqueChars(src.slice(i + 1, end).join(''));
        if (!set.length) throw new GenError('Empty [ ] set in pattern.');
        parts.push({ set });
        i = end;
      } else if (ch === '{') {
        const end = src.indexOf('}', i + 1);
        const n = end === -1 ? NaN : Number(src.slice(i + 1, end).join(''));
        if (!Number.isInteger(n) || n < 1) throw new GenError('Use {n} with a whole number, like d{4}.');
        if (!parts.length) throw new GenError('{n} must follow something to repeat.');
        const prev = parts[parts.length - 1];
        for (let k = 1; k < n; k++) parts.push(prev);
        i = end;
      } else if (ch === 'w' || ch === 'W') {
        parts.push({ word: ch === 'W' });
      } else if (PATTERN_TOKENS[ch]) {
        parts.push({ set: Array.from(PATTERN_TOKENS[ch]) });
      } else {
        parts.push({ lit: ch });
      }
      if (parts.length > 1024) throw new GenError('Pattern is too long (max 1024 pieces).');
    }
    return parts;
  }

  function genPattern(o) {
    const pattern = o.t_pattern || '';
    if (!pattern.trim()) throw new GenError('Write a pattern to forge from.');
    const parts = parsePattern(pattern);
    const words = window.DP_WORDS.both;
    let bits = 0;
    let value = '';
    for (const part of parts) {
      if (part.lit !== undefined) value += part.lit;
      else if (part.set) { value += rand.pick(part.set); bits += log2(part.set.length); }
      else {
        const w = rand.pick(words);
        value += part.word ? w[0].toUpperCase() + w.slice(1) : w;
        bits += log2(words.length);
      }
    }
    return { value, bits, info: `${parts.length} pieces · ${bits.toFixed(1)} bits of randomness` };
  }

  const COMMON_PINS = new Set(['1234', '1111', '0000', '1212', '7777', '1004', '2000', '4444', '2222', '6969',
    '9999', '3333', '5555', '6666', '1122', '1313', '8888', '4321', '2001', '1010', '2580', '0852', '1357',
    '123456', '654321', '111111', '000000', '121212', '112233', '696969', '123123', '159753', '147258',
    '789456', '123321', '666666', '252525', '1234567', '12345678', '87654321', '11111111']);

  function genPin(o) {
    const len = clamp(o.n_length, 4, 32);
    if (o.n_unique && len > 10) throw new GenError('Only 10 distinct digits exist — shorten the PIN or allow repeats.');
    const isCommon = pin =>
      COMMON_PINS.has(pin) ||
      (len === 4 && /^(19|20)\d\d$/.test(pin)) ||
      /^(\d)\1+$/.test(pin) ||
      /^(\d\d)\1+$/.test(pin);

    for (let attempt = 0; attempt < 5000; attempt++) {
      const pool = [...DIGITS];
      let pin = '';
      for (let i = 0; i < len; i++) {
        const idx = rand.int(pool.length);
        pin += pool[idx];
        if (o.n_unique) pool.splice(idx, 1);
      }
      if (o.n_noRepeat && /(\d)\1/.test(pin)) continue;
      if (o.n_noSeq && [...pin].some((_, i) => i >= 2 && isRun(pin[i - 2], pin[i - 1], pin[i]))) continue;
      if (o.n_noCommon && isCommon(pin)) continue;

      let bits = 0;
      for (let i = 0; i < len; i++) bits += log2(o.n_unique ? 10 - i : 10);
      if (o.n_noRepeat) bits = Math.min(bits, log2(10) + (len - 1) * log2(9));
      return { value: pin, bits, info: `${len} digits · about ${bits.toFixed(1)} bits` };
    }
    throw new GenError('Couldn’t find a PIN that satisfies every rule.');
  }

  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

  function toBase58(bytes) {
    let n = 0n;
    for (const b of bytes) n = (n << 8n) | BigInt(b);
    let out = '';
    while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
    for (const b of bytes) { if (b !== 0) break; out = '1' + out; }
    return out;
  }
  function toBase32(bytes, pad) {
    let out = '';
    let buf = 0;
    let bitsIn = 0;
    for (const b of bytes) {
      buf = (buf << 8) | b;
      bitsIn += 8;
      while (bitsIn >= 5) { out += B32[(buf >>> (bitsIn - 5)) & 31]; bitsIn -= 5; }
    }
    if (bitsIn > 0) out += B32[(buf << (5 - bitsIn)) & 31];
    if (pad) while (out.length % 8) out += '=';
    return out;
  }
  function toBase64(bytes) {
    let bin = '';
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  function genKey(o) {
    if (o.k_format === 'uuid') {
      const b = rand.bytes(16);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      const h = [...b].map(x => x.toString(16).padStart(2, '0')).join('');
      return {
        value: `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`,
        bits: 122,
        info: 'RFC 4122 version 4 · 122 random bits',
      };
    }
    const n = clamp(o.k_bytes, 4, 128);
    const bytes = rand.bytes(n);
    let value;
    switch (o.k_format) {
      case 'HEX': value = [...bytes].map(x => x.toString(16).padStart(2, '0')).join('').toUpperCase(); break;
      case 'base64': value = toBase64(bytes); if (!o.k_pad) value = value.replace(/=+$/, ''); break;
      case 'base64url': value = toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_'); if (!o.k_pad) value = value.replace(/=+$/, ''); break;
      case 'base32': value = toBase32(bytes, o.k_pad); break;
      case 'base58': value = toBase58(bytes); break;
      default: value = [...bytes].map(x => x.toString(16).padStart(2, '0')).join('');
    }
    const group = Number(o.k_group) || 0;
    if (group > 0) value = value.match(new RegExp(`.{1,${group}}`, 'g')).join(o.k_sep ?? '');
    return { value, bits: n * 8, info: `${n} random bytes · ${n * 8} bits` };
  }

  const GENERATORS = {
    random: genRandom,
    passphrase: genPassphrase,
    pronounce: genPronounceable,
    pattern: genPattern,
    pin: genPin,
    keys: genKey,
  };

  // ---------------------------------------------------------------------------
  // Strength & crack-time
  // ---------------------------------------------------------------------------
  const TIERS = [
    { min: 0, name: 'Hatchling', desc: 'Cracked before it can spread its wings.' },
    { min: 28, name: 'Wyrmling', desc: 'Weak — only for throwaway use.' },
    { min: 40, name: 'Drake', desc: 'Holds against online guessing, not against a stolen database.' },
    { min: 60, name: 'Wyvern', desc: 'Strong enough for most accounts.' },
    { min: 80, name: 'Dragon', desc: 'Very strong — a hoard well guarded.' },
    { min: 100, name: 'Elder Dragon', desc: 'Excellent. Fit for a master password.' },
    { min: 128, name: 'Ancient Wyrm', desc: 'Beyond any brute force. Legendary.' },
  ];
  const tierFor = bits => {
    let idx = 0;
    TIERS.forEach((t, i) => { if (bits >= t.min) idx = i; });
    return { ...TIERS[idx], index: idx };
  };

  const BIG_NAMES = [
    [1e3, 'thousand'], [1e6, 'million'], [1e9, 'billion'], [1e12, 'trillion'], [1e15, 'quadrillion'],
  ];
  const UNIVERSE_YEARS = 1.38e10;

  // Average time = half the keyspace / guesses per second. Worked in log10 to survive huge numbers.
  function crackTime(bits, rate) {
    const log10s = (bits - 1) * Math.log10(2) - Math.log10(rate);
    if (bits < 1 || log10s < 0) return 'Instantly';
    const s = 10 ** log10s;
    const fmt = (v, unit) => {
      const r = v < 10 ? Math.round(v * 10) / 10 : Math.round(v);
      return `${r} ${unit}${r === 1 ? '' : 's'}`;
    };
    if (s < 60) return fmt(s, 'second');
    if (s < 3600) return fmt(s / 60, 'minute');
    if (s < 86400) return fmt(s / 3600, 'hour');
    if (s < 86400 * 365.25) return fmt(s / 86400, 'day');

    const log10y = log10s - Math.log10(31557600);
    let text;
    if (log10y < 3) text = fmt(10 ** log10y, 'year');
    else if (log10y < 18) {
      const [div, name] = BIG_NAMES.filter(([d]) => log10y >= Math.log10(d)).pop();
      const v = 10 ** log10y / div;
      text = `${v < 10 ? v.toFixed(1) : Math.round(v)} ${name} years`;
    } else {
      text = `10<sup>${Math.floor(log10y)}</sup> years`;
    }
    if (log10y > Math.log10(UNIVERSE_YEARS)) {
      const ratio = log10y - Math.log10(UNIVERSE_YEARS);
      text += ratio < 3 ? ` <span class="muted">(${Math.round(10 ** ratio).toLocaleString()}× the universe’s age)</span>` : '';
    }
    return text;
  }

  // ---------------------------------------------------------------------------
  // UI state
  // ---------------------------------------------------------------------------
  const form = $('#options');
  const outputEl = $('#output');
  const STORE_KEY = 'dragonpass.settings.v1';
  const state = {
    mode: 'random',
    masked: false,
    current: '',
    batch: [],
    bits: 0,
    history: [],
  };

  const storage = {
    load() { try { return JSON.parse(localStorage.getItem(STORE_KEY)) || null; } catch { return null; } },
    save(data) { try { localStorage.setItem(STORE_KEY, JSON.stringify(data)); } catch { /* storage unavailable */ } },
  };

  function readOptions() {
    const o = {};
    for (const el of $$('[name]', form)) {
      if (el.type === 'checkbox') o[el.name] = el.checked;
      else if (el.type === 'radio') { if (el.checked) o[el.name] = el.value; }
      else if (el.type === 'range' || el.type === 'number') o[el.name] = Number(el.value);
      else o[el.name] = el.value;
    }
    return o;
  }

  function writeOption(name, value) {
    const el = form.elements[name];
    if (!el) return;
    if (el.type === 'checkbox') el.checked = !!value;
    else el.value = value;
    if (el.type === 'range') syncRange(el);
  }

  function saveSettings() {
    storage.save({ mode: state.mode, options: readOptions() });
  }

  function restoreSettings() {
    const saved = storage.load();
    if (!saved) return;
    if (saved.options) for (const [k, v] of Object.entries(saved.options)) writeOption(k, v);
    if (saved.mode && GENERATORS[saved.mode]) setMode(saved.mode, false);
  }

  // range <-> number pairs
  function syncRange(range) {
    const num = range.parentElement.querySelector('input[type="number"]');
    if (num) num.value = range.value;
    const pct = ((range.value - range.min) / (range.max - range.min)) * 100;
    range.style.setProperty('--fill', `${pct}%`);
  }
  for (const pair of $$('.range-pair')) {
    const range = $('input[type="range"]', pair);
    const num = $('input[type="number"]', pair);
    range.addEventListener('input', () => syncRange(range));
    num.addEventListener('input', () => {
      if (num.value === '') return;
      range.value = clamp(Number(num.value), Number(range.min), Number(range.max));
      syncRange(range);
      onOptionsChanged();
    });
    num.addEventListener('change', () => { num.value = range.value; });
    syncRange(range);
  }

  function updateConditionalFields() {
    const o = readOptions();
    for (const el of $$('[data-show-when]')) {
      const [name, value] = el.dataset.showWhen.split('=');
      el.hidden = String(o[name]) !== value;
    }
    const histList = $('#history');
    histList.classList.toggle('blur', !!o.blurHistory);
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------
  function colorize(str) {
    const frag = document.createDocumentFragment();
    let run = '';
    let runClass = '';
    const flush = () => {
      if (!run) return;
      const span = document.createElement('span');
      span.className = runClass;
      span.textContent = run;
      frag.appendChild(span);
      run = '';
    };
    for (const ch of Array.from(str)) {
      const cls = charClass(ch);
      if (cls !== runClass) { flush(); runClass = cls; }
      run += ch;
    }
    flush();
    return frag;
  }

  function renderOutput() {
    outputEl.replaceChildren();
    const wrap = document.createElement('span');
    wrap.className = 'pw';
    if (!state.current) {
      wrap.textContent = '';
    } else if (state.masked) {
      wrap.className = 'pw masked';
      wrap.textContent = '•'.repeat(Math.min(Array.from(state.current).length, 64));
    } else {
      wrap.appendChild(colorize(state.current));
    }
    outputEl.appendChild(wrap);
    $('#btn-mask').setAttribute('aria-pressed', String(state.masked));
  }

  function setMeter(meter, index) {
    $$('span', meter).forEach((s, i) => s.classList.toggle('on', index >= 0 && i <= index));
  }

  function renderStrength() {
    const o = readOptions();
    const tier = tierFor(state.bits);
    setMeter($('#meter'), state.current ? tier.index : -1);
    $('#tier-name').textContent = state.current ? tier.name : '—';
    $('#tier-desc').textContent = state.current ? tier.desc : '';
    $('#stat-bits').textContent = state.current ? `≈ ${state.bits.toFixed(1)} bits` : '—';
    $('#stat-length').textContent = state.current ? `${Array.from(state.current).length} chars` : '—';
    $('#stat-crack').innerHTML = state.current ? crackTime(state.bits, Number(o.rate) || 1e10) : '—';
  }

  const ICON_COPY = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12V1zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2zm0 16H8V7h11v14z"/></svg>';

  function listItem(value, meta) {
    const li = document.createElement('li');
    const pw = document.createElement('span');
    pw.className = 'pw';
    pw.appendChild(colorize(value));
    li.appendChild(pw);
    if (meta) {
      const m = document.createElement('span');
      m.className = 'meta';
      m.textContent = meta;
      li.appendChild(m);
    }
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'icon-btn';
    btn.title = 'Copy';
    btn.innerHTML = ICON_COPY + '<span class="visually-hidden">Copy</span>';
    btn.addEventListener('click', () => copy(value));
    li.appendChild(btn);
    return li;
  }

  function renderBulk() {
    const bulk = $('#bulk');
    if (state.batch.length <= 1) { bulk.hidden = true; return; }
    bulk.hidden = false;
    $('#bulk-count').textContent = `(${state.batch.length})`;
    const list = $('#bulk-list');
    list.replaceChildren(...state.batch.map(v => listItem(v)));
  }

  function renderHistory() {
    const list = $('#history');
    list.replaceChildren(...state.history.map(h => listItem(h.value, h.time)));
  }

  function setError(msg) {
    const el = $('#error');
    el.hidden = !msg;
    el.textContent = msg || '';
  }

  function setPanelInfo(text) {
    const el = $(`[data-info="${state.mode}"]`);
    if (el) el.textContent = text || '';
  }

  // ---------------------------------------------------------------------------
  // Actions
  // ---------------------------------------------------------------------------
  function generate({ animate = true, record = true } = {}) {
    const o = readOptions();
    const qty = clamp(o.qty, 1, 500);
    const gen = GENERATORS[state.mode];
    const batch = [];
    let last;
    try {
      for (let i = 0; i < qty; i++) {
        last = gen(o);
        batch.push(last.value);
      }
    } catch (err) {
      if (!(err instanceof GenError)) console.error(err);
      setError(err instanceof GenError ? err.message : 'Something went wrong forging that password.');
      setPanelInfo('');
      return;
    }
    setError(null);
    state.batch = batch;
    state.current = batch[0];
    state.bits = last.bits;
    setPanelInfo(last.info);

    renderOutput();
    renderStrength();
    renderBulk();

    if (animate) {
      outputEl.classList.remove('forged');
      void outputEl.offsetWidth;
      outputEl.classList.add('forged');
    }
    if (record) addHistory(state.current);
    if (o.autoCopy && record) copy(qty > 1 ? batch.join('\n') : state.current, true);
  }

  function addHistory(value) {
    if (!readOptions().keepHistory || !value || state.history[0]?.value === value) return;
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    state.history.unshift({ value, time });
    state.history.length = Math.min(state.history.length, 100);
    renderHistory();
  }

  let toastTimer;
  function toast(msg) {
    const el = $('#toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 1600);
  }

  async function copy(text, quiet = false) {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch { toast('Copy failed — select and copy manually'); ta.remove(); return; }
      ta.remove();
    }
    toast(quiet ? 'Forged & copied' : 'Copied to your hoard');
  }

  function download() {
    const blob = new Blob([state.batch.join('\n') + '\n'], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
    a.href = url;
    a.download = `dragonpass-${stamp}.txt`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function setMode(mode, regen = true) {
    state.mode = mode;
    for (const tab of $$('.tabs [role="tab"]')) tab.setAttribute('aria-selected', String(tab.dataset.mode === mode));
    for (const panel of $$('[data-panel]')) panel.hidden = panel.dataset.panel !== mode;
    if (regen) {
      saveSettings();
      generate();
    }
  }

  const PRESETS = {
    balanced: { r_length: 20, sets: ['upper', 'lower', 'digits', 'symbols'], r_requireEach: true },
    fortress: { r_length: 48, sets: ['upper', 'lower', 'digits', 'symbols', 'punct', 'brackets', 'math', 'quotes', 'slashes'], r_requireEach: true },
    readable: { r_length: 16, sets: ['upper', 'lower', 'digits'], r_noSimilar: true, r_noAmbiguous: true, r_noConsec: true, r_requireEach: true },
    legacy: { r_length: 12, sets: ['upper', 'lower', 'digits'], r_requireEach: true, r_startLetter: true },
    wifi: { r_length: 24, sets: ['upper', 'lower', 'digits'], r_noSimilar: true, r_noAmbiguous: true, r_requireEach: true },
    arcane: { r_length: 24, sets: ['upper', 'lower', 'digits', 'symbols', 'greek', 'runes'], r_requireEach: true },
  };

  function applyPreset(name) {
    const p = PRESETS[name];
    if (!p) return;
    for (const cs of CHARSETS) writeOption('r_' + cs.key, p.sets.includes(cs.key));
    writeOption('r_useCustom', false);
    writeOption('r_symbolChars', '!@#$%^&*');
    for (const k of ['r_noSimilar', 'r_noAmbiguous', 'r_noDup', 'r_noConsec', 'r_noSeq', 'r_startLetter', 'r_noEdgeSpecial']) {
      writeOption(k, !!p[k]);
    }
    for (const k of ['r_minUpper', 'r_minLower', 'r_minDigits', 'r_minSpecial']) writeOption(k, 0);
    writeOption('r_exclude', '');
    writeOption('r_requireEach', !!p.r_requireEach);
    writeOption('r_length', p.r_length);
    onOptionsChanged();
  }

  // Options that only affect presentation shouldn't re-roll the password
  const PRESENTATION_ONLY = new Set(['rate', 'autoCopy', 'keepHistory', 'blurHistory']);

  let regenTimer;
  function onOptionsChanged(e) {
    updateConditionalFields();
    saveSettings();
    const name = e?.target?.name;
    if (name && PRESENTATION_ONLY.has(name)) { renderStrength(); return; }
    clearTimeout(regenTimer);
    regenTimer = setTimeout(() => generate({ record: false }), 60);
  }

  // ---------------------------------------------------------------------------
  // Password tester
  // ---------------------------------------------------------------------------
  const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qazwsxedc', '!@#$%^&*()'];
  const TESTER_WORDS = [...window.DP_WORDS.both, ...window.DP_COMMON_PASSWORDS]
    .filter(w => w.length >= 4)
    .sort((a, b) => b.length - a.length);

  function analyze(pw) {
    const chars = Array.from(pw);
    const notes = [];
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[\x20-\x2f\x3a-\x40\x5b-\x60\x7b-\x7e]/.test(pw)) pool += 33;
    if (/[^\x00-\x7f]/.test(pw)) pool += 100;
    const perChar = log2(Math.max(pool, 2));
    let bits = chars.length * perChar;
    const lower = pw.toLowerCase();
    const unleet = lower.replace(/[4@]/g, 'a').replace(/3/g, 'e').replace(/[1!]/g, 'i').replace(/0/g, 'o').replace(/[5$]/g, 's').replace(/7/g, 't');

    if (window.DP_COMMON_PASSWORDS.has(lower) || window.DP_COMMON_PASSWORDS.has(unleet) ||
        window.DP_COMMON_PASSWORDS.has(lower.replace(/\d+$/, ''))) {
      notes.push(['warn', 'This is one of the most common passwords — it would fall in seconds.']);
      bits = Math.min(bits, 8);
    }

    // Penalise predictable stretches: repeats, runs, keyboard walks
    let penalty = 0;
    let repeatChars = 0;
    for (let i = 1; i < chars.length; i++) if (chars[i] === chars[i - 1]) repeatChars++;
    if (repeatChars) { penalty += repeatChars * perChar * 0.8; if (repeatChars >= 2) notes.push(['warn', 'Repeated characters make it easier to guess.']); }

    let runChars = 0;
    for (let i = 2; i < chars.length; i++) if (isRun(chars[i - 2], chars[i - 1], chars[i])) runChars++;
    if (runChars) { penalty += runChars * perChar * 0.8; notes.push(['warn', 'Contains sequences like “abc” or “123”.']); }

    let walk = false;
    for (const row of KEYBOARD_ROWS) {
      for (let i = 0; i + 4 <= row.length; i++) {
        const seg = row.slice(i, i + 4);
        if (lower.includes(seg) || lower.includes([...seg].reverse().join(''))) { walk = true; penalty += 3 * perChar; }
      }
    }
    if (walk) notes.push(['warn', 'Contains a keyboard pattern like “qwer” or “asdf”.']);

    // Dictionary words: each found word counts as one pick from a ~10k-word list instead of n random characters
    let remaining = unleet;
    const found = [];
    for (const w of TESTER_WORDS) {
      if (found.length >= 6) break;
      const idx = remaining.indexOf(w);
      if (idx !== -1) {
        found.push(w);
        penalty += Math.max(0, w.length * perChar - 14);
        remaining = remaining.slice(0, idx) + '\0'.repeat(w.length) + remaining.slice(idx + w.length);
      }
    }
    if (found.length) {
      notes.push(['', `Dictionary words found: ${found.map(w => `“${w}”`).join(', ')}. Words are guessed whole, not letter by letter.`]);
    }
    if (/(19|20)\d\d/.test(pw)) { penalty += 6; notes.push(['warn', 'Looks like it contains a year.']); }

    bits = Math.max(Math.min(bits, chars.length * 1.5), bits - penalty);
    if (chars.length < 12) notes.push(['warn', 'Shorter than 12 characters. Length is the cheapest strength you can buy.']);
    if (pool <= 36 && chars.length < 20) notes.push(['', 'Mixing cases, digits and symbols widens the search space.']);
    if (bits >= 80 && !notes.some(n => n[0] === 'warn')) notes.push(['good', 'No obvious weaknesses found.']);
    return { bits, pool, length: chars.length, notes };
  }

  function renderTester() {
    const pw = $('#tester').value;
    const out = $('#tester-result');
    if (!pw) {
      setMeter($('#tester-meter'), -1);
      out.className = 'tester-result muted';
      out.textContent = 'Nothing is sent anywhere — the check runs in your browser.';
      return;
    }
    const a = analyze(pw);
    const tier = tierFor(a.bits);
    setMeter($('#tester-meter'), tier.index);
    out.className = 'tester-result';
    out.replaceChildren();

    const head = document.createElement('div');
    head.className = 't-head';
    head.innerHTML = `<strong></strong><span class="muted"></span>`;
    head.firstChild.textContent = tier.name;
    head.lastChild.innerHTML = `≈ ${a.bits.toFixed(1)} bits · ${a.length} chars · cracked in ${crackTime(a.bits, Number(readOptions().rate) || 1e10)}`;
    out.appendChild(head);

    if (a.notes.length) {
      const ul = document.createElement('ul');
      for (const [cls, text] of a.notes) {
        const li = document.createElement('li');
        if (cls) li.className = cls;
        li.textContent = text;
        ul.appendChild(li);
      }
      out.appendChild(ul);
    }
  }

  // ---------------------------------------------------------------------------
  // Ember particles
  // ---------------------------------------------------------------------------
  function startEmbers() {
    const canvas = $('#embers');
    if (!canvas.getContext || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    const ctx = canvas.getContext('2d');
    let w, h, dpr;
    const embers = [];
    const resize = () => {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.width = innerWidth * dpr;
      h = canvas.height = innerHeight * dpr;
    };
    const spawn = (initial) => ({
      x: Math.random() * w,
      y: initial ? Math.random() * h : h + 10 * dpr,
      r: (Math.random() * 1.8 + 0.6) * dpr,
      vy: (Math.random() * 0.5 + 0.25) * dpr,
      vx: (Math.random() - 0.5) * 0.3 * dpr,
      life: Math.random() * 0.6 + 0.4,
      phase: Math.random() * Math.PI * 2,
    });
    resize();
    addEventListener('resize', resize);
    const count = Math.round(Math.min(60, innerWidth / 22));
    for (let i = 0; i < count; i++) embers.push(spawn(true));

    let running = true;
    document.addEventListener('visibilitychange', () => {
      running = !document.hidden;
      if (running) requestAnimationFrame(tick);
    });

    function tick(t) {
      if (!running) return;
      ctx.clearRect(0, 0, w, h);
      ctx.globalCompositeOperation = 'lighter';
      for (let i = 0; i < embers.length; i++) {
        const e = embers[i];
        e.y -= e.vy;
        e.x += e.vx + Math.sin(t / 1400 + e.phase) * 0.25 * dpr;
        const fade = Math.max(0, Math.min(1, e.y / h)) * e.life;
        if (e.y < -10) { embers[i] = spawn(false); continue; }
        const g = ctx.createRadialGradient(e.x, e.y, 0, e.x, e.y, e.r * 4);
        g.addColorStop(0, `rgba(255, 200, 120, ${0.9 * fade})`);
        g.addColorStop(0.35, `rgba(255, 110, 40, ${0.5 * fade})`);
        g.addColorStop(1, 'rgba(200, 30, 20, 0)');
        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(e.x, e.y, e.r * 4, 0, Math.PI * 2);
        ctx.fill();
      }
      requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // ---------------------------------------------------------------------------
  // Wiring
  // ---------------------------------------------------------------------------
  form.addEventListener('submit', e => e.preventDefault());
  form.addEventListener('input', e => { if (e.target.name) onOptionsChanged(e); });
  form.addEventListener('change', e => { if (e.target.name && e.target.tagName === 'SELECT') onOptionsChanged(e); });

  $('#btn-generate').addEventListener('click', () => generate());
  $('#btn-copy').addEventListener('click', () => { copy(state.current); addHistory(state.current); });
  $('#btn-mask').addEventListener('click', () => { state.masked = !state.masked; renderOutput(); });
  $('#btn-copy-all').addEventListener('click', () => copy(state.batch.join('\n')));
  $('#btn-download').addEventListener('click', download);
  $('#btn-clear-history').addEventListener('click', () => { state.history = []; renderHistory(); });

  for (const tab of $$('.tabs [role="tab"]')) tab.addEventListener('click', () => setMode(tab.dataset.mode));
  $('.tabs').addEventListener('keydown', e => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const tabs = $$('.tabs [role="tab"]');
    const i = tabs.findIndex(t => t.dataset.mode === state.mode);
    const next = tabs[(i + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length];
    next.focus();
    setMode(next.dataset.mode);
  });

  for (const chip of $$('[data-preset]')) chip.addEventListener('click', () => applyPreset(chip.dataset.preset));
  for (const chip of $$('[data-pattern]')) {
    chip.addEventListener('click', () => { writeOption('t_pattern', chip.dataset.pattern); onOptionsChanged(); });
  }

  $('#tester').addEventListener('input', renderTester);
  $('#btn-tester-mask').addEventListener('click', e => {
    const input = $('#tester');
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    e.currentTarget.setAttribute('aria-pressed', String(show));
  });

  document.addEventListener('keydown', e => {
    if (e.metaKey || e.ctrlKey || e.altKey) return;
    if (e.target.closest('input, select, textarea')) return;
    const k = e.key.toLowerCase();
    if (k === 'g') { e.preventDefault(); generate(); }
    else if (k === 'c') { e.preventDefault(); copy(state.current); addHistory(state.current); }
    else if (k === 'h') { e.preventDefault(); state.masked = !state.masked; renderOutput(); }
  });

  restoreSettings();
  updateConditionalFields();
  generate({ animate: false });
  renderHistory();
  startEmbers();
})();
