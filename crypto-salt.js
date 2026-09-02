/**
 * Coralgenz Global - Ultra-Fast Cryptographic Salted Hash QR Security Engine
 * =========================================================================
 * Generates lightweight, low-density, tamper-proof salted hash tokens for QR codes.
 * Standardized for 5 Tracks: Java, Python, C, Web Development, Fullstack.
 * Standardized Duration: 1 Month.
 */

// Enterprise signing salt & secret pepper (HMAC-SHA256)
const ENTERPRISE_PEPPER = "CORALGENZ_MSME_GOVT_SALT_2026_SECURE_KEY_8842_TAMPER_PROOF";
const TOKEN_PREFIX_COMPACT = "CGZ";
const TOKEN_PREFIX_V1 = "CGZ-SALTED-V1";

// 5 Standard Internship & Assessment Tracks
export const TRACK_MAP = {
  "JAVA": "Java",
  "PYTHON": "Python",
  "C": "C",
  "WEB": "Web Development",
  "FULLSTACK": "Fullstack"
};

// Reverse Mapping
export function getTrackCode(fullTrack) {
  if (!fullTrack) return "FULLSTACK";
  const str = fullTrack.toLowerCase();
  if (str.includes("java")) return "JAVA";
  if (str.includes("python")) return "PYTHON";
  if (str === "c" || str.includes("c programming") || str.includes("cpp") || str.includes("c++")) return "C";
  if (str.includes("web") && !str.includes("full")) return "WEB";
  if (str.includes("full") || str.includes("mern") || str.includes("fsw")) return "FULLSTACK";
  return fullTrack;
}

export function expandTrackName(code) {
  if (!code) return "Fullstack";
  const upper = code.toUpperCase();
  if (TRACK_MAP[upper]) return TRACK_MAP[upper];
  const lower = code.toLowerCase();
  if (lower.includes("java")) return "Java";
  if (lower.includes("python")) return "Python";
  if (lower === "c" || lower.includes("c programming")) return "C";
  if (lower.includes("web") && !lower.includes("full")) return "Web Development";
  if (lower.includes("full") || lower.includes("mern") || lower === "fsw") return "Fullstack";
  return code;
}

// Helper: Base64URL Encoding (Safe for URLs & QR Codes) with UTF-8 support
export function base64UrlEncode(str) {
  const utf8Bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < utf8Bytes.length; i++) {
    binary += String.fromCharCode(utf8Bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Helper: Base64URL Decoding with UTF-8 support
export function base64UrlDecode(base64UrlStr) {
  let base64 = base64UrlStr.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

// Pure JavaScript SHA-256 Implementation
function sha256Sync(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  
  const mathPow = Math.pow;
  let i, j;
  let result = "";

  const words = [];
  const asciiBitLength = ascii.length * 8;

  let hash = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ];

  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  for (i = 0; i < ascii.length; i++) {
    j = ascii.charCodeAt(i);
    words[i >> 2] |= j << ((3 - (i % 4)) * 8);
  }

  words[asciiBitLength >> 5] |= 0x80 << (24 - (asciiBitLength % 32));
  words[(((asciiBitLength + 64) >> 9) << 4) + 15] = asciiBitLength;

  for (i = 0; i < words.length; i += 16) {
    let w = words.slice(i, i + 16);
    let oldHash = hash.slice(0);

    for (j = 0; j < 64; j++) {
      let w15 = w[j - 15], w2 = w[j - 2];

      let s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      let s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      let ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      let maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);

      let temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[j] + (j < 16 ? w[j] : (w[j] = (w[j - 16] + s0 + w[j - 7] + s1) | 0))) | 0;
      let temp2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj) | 0;

      hash = [(temp1 + temp2) | 0, hash[0], hash[1], hash[2], (hash[3] + temp1) | 0, hash[4], hash[5], hash[6]];
    }

    for (j = 0; j < 8; j++) {
      hash[j] = (hash[j] + oldHash[j]) | 0;
    }
  }

  for (i = 0; i < 8; i++) {
    for (j = 3; j >= 0; j--) {
      let b = (hash[i] >> (j * 8)) & 255;
      result += (b < 16 ? "0" : "") + b.toString(16);
    }
  }

  return result;
}

export function generateRandomSalt(length = 8) {
  const chars = "abcdef0123456789";
  let salt = "";
  for (let i = 0; i < length; i++) {
    salt += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return salt;
}

export function computeSaltedHash(salt, dataPayload, compact = true) {
  const hmacInput = `${salt}:${ENTERPRISE_PEPPER}:${dataPayload}:${salt}`;
  const fullHash = sha256Sync(hmacInput);
  return compact ? fullHash.substring(0, 16) : fullHash;
}

export function isSaltedHashToken(str) {
  if (!str || typeof str !== "string") return false;
  str = str.trim();

  if (str.startsWith("http://") || str.startsWith("https://")) {
    try {
      const url = new URL(str);
      const tokenInUrl = url.searchParams.get("v") || url.searchParams.get("token") || url.searchParams.get("id");
      if (tokenInUrl) {
        str = tokenInUrl.trim();
      } else {
        return false;
      }
    } catch (e) {
      return false;
    }
  }

  if (str.startsWith(`${TOKEN_PREFIX_COMPACT}.`) || str.startsWith(`${TOKEN_PREFIX_V1}.`)) {
    const parts = str.split(".");
    return parts.length === 4;
  }

  return false;
}

/**
 * Generates an Ultra-Compact Tamper-Proof Salted Hash Token for candidate details.
 * Standardized for 5 Tracks: Java, Python, C, Web Development, Fullstack.
 * Standardized Duration: 1 Month.
 */
export function generateSaltedHashToken(candidateData, customSalt = null) {
  if (!candidateData) throw new Error("Candidate data is required");

  const salt = (customSalt || generateRandomSalt(8)).toLowerCase().trim();
  
  const name = (candidateData.name || candidateData.candidateName || "").trim();
  const email = (candidateData.email || "").trim().toLowerCase();
  const rawTrack = (candidateData.track || candidateData.course || "Fullstack").trim();
  const trackCode = getTrackCode(rawTrack);
  const serialNumber = (candidateData.serialNumber || candidateData.certId || "").trim();
  const issueDate = (candidateData.issueDate || "August 2026").trim();

  // Ultra-compact pipe-delimited payload: Name|Email|TrackCode|Serial|1Month|Date
  const compactPayload = `${name}|${email}|${trackCode}|${serialNumber}|1Month|${issueDate}`;
  const encodedPayload = base64UrlEncode(compactPayload);
  const signature = computeSaltedHash(salt, encodedPayload, true);

  // Format: CGZ.<salt8>.<encodedPayload>.<sig16>
  return `${TOKEN_PREFIX_COMPACT}.${salt}.${encodedPayload}.${signature}`;
}

/**
 * Decodes and verifies a Salted Hash Token from a QR code scan.
 */
export function verifyAndDecodeSaltedHash(rawInput) {
  if (!rawInput || typeof rawInput !== "string") {
    return {
      valid: false,
      error: "EMPTY_INPUT",
      message: "Please enter a valid cryptographic QR token."
    };
  }

  let cleanToken = rawInput.trim();

  if (cleanToken.startsWith("http://") || cleanToken.startsWith("https://")) {
    try {
      const url = new URL(cleanToken);
      const paramToken = url.searchParams.get("v") || 
                         url.searchParams.get("token") || 
                         url.searchParams.get("verify") || 
                         url.searchParams.get("id");
      
      if (paramToken) {
        cleanToken = paramToken.trim();
      }
    } catch (e) {}
  }

  const isCompact = cleanToken.startsWith(`${TOKEN_PREFIX_COMPACT}.`);
  const isV1 = cleanToken.startsWith(`${TOKEN_PREFIX_V1}.`);

  if (!isCompact && !isV1) {
    return {
      valid: false,
      error: "NORMAL_FORMAT_BLOCKED",
      isNormalFormat: true,
      rawInput: cleanToken,
      message: `Access Blocked: Unverified QR code.`
    };
  }

  const parts = cleanToken.split(".");
  if (parts.length !== 4) {
    return {
      valid: false,
      error: "INVALID_TOKEN_STRUCTURE",
      message: "Malformed token structure."
    };
  }

  const [prefix, salt, encodedPayload, receivedSignature] = parts;

  const isCompactSig = isCompact && receivedSignature.length <= 20;
  const expectedSignature = computeSaltedHash(salt, encodedPayload, isCompactSig);
  
  if (receivedSignature.toLowerCase() !== expectedSignature.toLowerCase()) {
    const fullExpected = computeSaltedHash(salt, encodedPayload, false);
    if (receivedSignature.toLowerCase() !== fullExpected.toLowerCase()) {
      return {
        valid: false,
        error: "TAMPERED_PAYLOAD",
        message: "⚠️ Verification Alert: Cryptographic signature mismatch. The certificate data has been altered."
      };
    }
  }

  try {
    const rawDecoded = base64UrlDecode(encodedPayload);
    let candidateData = null;

    if (rawDecoded.startsWith("{") && rawDecoded.endsWith("}")) {
      const parsed = JSON.parse(rawDecoded);
      candidateData = {
        name: parsed.name || parsed.candidateName || parsed.n || "Candidate",
        candidateName: parsed.candidateName || parsed.name || parsed.n || "Candidate",
        email: parsed.email || parsed.e || "—",
        track: expandTrackName(parsed.t || parsed.track || "Fullstack"),
        serialNumber: parsed.serialNumber || parsed.certId || parsed.s || "CG-MSME-2026",
        certId: parsed.certId || parsed.serialNumber || parsed.s || "CG-MSME-2026",
        duration: "1 Month",
        issueDate: parsed.issueDate || parsed.d || "August 2026",
        status: "100% Completed • MSME Verified Deliverables",
        issuingAuthority: "Coralgenz Global, Coimbatore, Tamil Nadu, India",
        msmeRegNo: "UDYAM-TN-03-0189422",
        verified: true
      };
    } else if (rawDecoded.includes("|")) {
      const segs = rawDecoded.split("|");
      const [cName, cEmail, cTrackCode, cSerial, , cDate] = segs;

      candidateData = {
        name: cName || "Candidate",
        candidateName: cName || "Candidate",
        email: cEmail || "—",
        track: expandTrackName(cTrackCode),
        serialNumber: cSerial || "CG-MSME-2026",
        certId: cSerial || "CG-MSME-2026",
        duration: "1 Month",
        issueDate: cDate || "August 2026",
        status: "100% Completed • MSME Verified Deliverables",
        issuingAuthority: "Coralgenz Global, Coimbatore, Tamil Nadu, India",
        msmeRegNo: "UDYAM-TN-03-0189422",
        verified: true
      };
    }

    if (!candidateData || (!candidateData.name && !candidateData.candidateName)) {
      return {
        valid: false,
        error: "MISSING_CANDIDATE_NAME",
        message: "Candidate payload is missing essential fields."
      };
    }

    return {
      valid: true,
      data: candidateData,
      salt: salt,
      signature: receivedSignature
    };
  } catch (err) {
    return {
      valid: false,
      error: "DECODE_ERROR",
      message: `Token Decode Error: ${err.message}`
    };
  }
}
