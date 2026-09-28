import axios from "axios";
import crypto from "crypto";

const BASE = "https://www.alightpro.my.id";

// Membuat instance axios dengan headers browser Android asli
const http = axios.create({
  baseURL: BASE,
  timeout: 15000,
  headers: {
    "accept": "application/json, text/plain, */*",
    "accept-language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "sec-ch-ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "sec-ch-ua-mobile": "?1",
    "sec-ch-ua-platform": '"Android"',
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-origin",
    "referer": `${BASE}/`,
    "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
  },
});

let _cookie = "";
http.interceptors.request.use(cfg => { 
  if (_cookie) cfg.headers["cookie"] = _cookie; 
  return cfg; 
});

http.interceptors.response.use(res => {
  const sc = res.headers["set-cookie"];
  if (sc) _cookie = sc.map(c => c.split(";")[0]).join("; ");
  return res;
});

async function sha256(str) {
  const buf = Buffer.from(str, "utf8");
  return crypto.createHash("sha256").update(buf).digest("hex");
}

async function solvePoW(sessionId, nonce, email, action, difficulty = "0000") {
  const prefix = `${sessionId}:${nonce}:${email.toLowerCase()}:${action}:`;
  for (let i = 0; i < 500000; i++) {
    const hash = await sha256(prefix + i);
    if (hash.startsWith(difficulty)) return String(i);
  }
  return String(Date.now());
}

async function getSession() {
  const { data } = await http.get("/api/session", {
    headers: { "x-requested-with": "XMLHttpRequest" },
  });
  if (!data.status || !data.token || !data.nonce)
    throw new Error("Session invalid: " + JSON.stringify(data));
  return data;
}

async function request(action, body) {
  const sess = await getSession();
  const { token, nonce, sessionId, difficulty = "0000" } = sess;

  const pow = await solvePoW(sessionId, nonce, body.email, action, difficulty);

  const { data } = await http.post("/api/alight-motion",
    { action, ...body },
    {
      headers: {
        "content-type": "application/json",
        "x-requested-with": "XMLHttpRequest",
        "x-amprem-token": token,
        "x-amprem-nonce": nonce,
        "x-amprem-pow": pow,
      },
    }
  );
  return data;
}

export async function handler(event, context) {
  const headers = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Content-Type": "application/json"
  };

  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers,
      body: JSON.stringify({ status: false, message: "Method not allowed" })
    };
  }

  try {
    const body = JSON.parse(event.body || "{}");
    const { action, email, link } = body;

    if (!action || !email) {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ status: false, message: "Parameter action dan email dibutuhkan" })
      };
    }

    if (action === "send") {
      const result = await request("send", { email });
      return { statusCode: 200, headers, body: JSON.stringify(result) };
    } else if (action === "verify") {
      if (!link) {
        return {
          statusCode: 400,
          headers,
          body: JSON.stringify({ status: false, message: "Parameter link dibutuhkan" })
        };
      }
      const result = await request("verify", { email, link });
      return { statusCode: 200, headers, body: JSON.stringify(result) };
    } else {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ status: false, message: "Action tidak dikenal" })
      };
    }
  } catch (error) {
    const errorMsg = error.response?.data?.message || error.message || "Terjadi kesalahan internal server";
    return {
      statusCode: error.response?.status || 500,
      headers,
      body: JSON.stringify({
        status: false,
        message: errorMsg
      })
    };
  }
}
