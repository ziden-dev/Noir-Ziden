// Many of these utilities are from the `big-integer` library,
// but adjusted to only work with native BigInt type
// Ref https://github.com/peterolson/BigInteger.js/blob/e5d2154d3c417069c51e7116bafc3b91d0b9fe41/BigInteger.js
// Originally licensed The Unlicense

export function compare(a, b) {
  return a === b ? 0 : a > b ? 1 : -1;
}

export function square(n) {
  return n * n;
}

export function isOdd(n) {
  return n % 2n !== 0n;
}

export function isEven(n) {
  return n % 2n === 0n;
}

export function isNegative(n) {
  return n < 0n;
}

export function isPositive(n) {
  return n > 0n;
}

export function bitLength(n) {
  if (isNegative(n)) {
    return n.toString(2).length - 1; // discard the - sign
  } else {
    return n.toString(2).length;
  }
}

export function abs(n) {
  return n < 0n ? -n : n;
}

export function isUnit(n) {
  return abs(n) === 1n;
}

export function pow(a, b) {
  if(BigInt(a) === 0n) return BigInt(0);
  if(BigInt(b) === 0n) return BigInt(1);
  const bbits = BigInt(b).toString(2);
  let result = BigInt(0);
  for (let i = 0; i < bbits.length; i++) {
    result = result << BigInt(1);
    if (bbits[i] == '1') {
      result = result + BigInt(a);
    }
  }
  return result;
}

export function modInv(a, n) {
  var t = 0n,
    newT = 1n,
    r = n,
    newR = abs(a),
    q,
    lastT,
    lastR;
  while (newR !== 0n) {
    q = r / newR;
    lastT = t;
    lastR = r;
    t = newT;
    r = newR;
    newT = lastT - q * newT;
    newR = lastR - q * newR;
  }
  if (!isUnit(r)) throw new Error(a.toString() + ' and ' + n.toString() + ' are not co-prime');
  if (compare(t, 0n) === -1) {
    t = t + n;
  }
  if (isNegative(a)) {
    return -t;
  }
  return t;
}

export function modPow(n, exp, mod) {
  if (mod === 0n) throw new Error('Cannot take modPow with modulus 0');
  var r = 1n,
    base = n % mod;
  if (isNegative(exp)) {
    exp = exp * -1n;
    base = modInv(base, mod);
  }
  while (isPositive(exp)) {
    if (base === 0n) return 0n;
    if (isOdd(exp)) r = (r * base) % mod;
    exp = exp / 2n;
    base = square(base) % mod;
  }
  return r;
}

export function compareAbs(a, b) {
  a = a >= 0n ? a : -a;
  b = b >= 0n ? b : -b;
  return a === b ? 0 : a > b ? 1 : -1;
}

export function isDivisibleBy(a, n) {
  if (n === 0n) return false;
  if (isUnit(n)) return true;
  if (compareAbs(n, 2n) === 0) return isEven(a);
  return a % n === 0n;
}

export function isBasicPrime(v) {
  var n = abs(v);
  if (isUnit(n)) return false;
  if (n === 2n || n === 3n || n === 5n) return true;
  if (isEven(n) || isDivisibleBy(n, 3n) || isDivisibleBy(n, 5n)) return false;
  if (n < 49n) return true;
  // we don't know if it's prime: let the other functions figure it out
}

export function prev(n) {
  return n - 1n;
}

export function millerRabinTest(n, a) {
  var nPrev = prev(n),
    b = nPrev,
    r = 0,
    d,
    i,
    x;
  while (isEven(b)) (b = b / 2n), r++;
  next: for (i = 0; i < a.length; i++) {
    if (n < a[i]) continue;
    x = modPow(BigInt(a[i]), b, n);
    if (isUnit(x) || x === nPrev) continue;
    for (d = r - 1; d != 0; d--) {
      x = square(x) % n;
      if (isUnit(x)) return false;
      if (x === nPrev) continue next;
    }
    return false;
  }
  return true;
}

export function isPrime(p) {
  var isPrime = isBasicPrime(p);
  if (isPrime !== undefined) return isPrime;
  var n = abs(p);
  var bits = bitLength(n);
  if (bits <= 64) return millerRabinTest(n, [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]);
  var logN = Math.log(2) * Number(bits);
  var t = Math.ceil(logN);
  for (var a = [], i = 0; i < t; i++) {
    a.push(BigInt(i + 2));
  }
  return millerRabinTest(n, a);
}
