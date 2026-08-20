import crypto from "crypto";

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || "ghasemiiliya07@gmail.com"
)
  .trim()
  .toLowerCase();

const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;

const DOMAIN = "https://brightstars.ir";
const REDIRECT_URI = `${DOMAIN}/.netlify/functions/auth`;

const SESSION_MAX_AGE = 60 * 60 * 24 * 7;
const OAUTH_STATE_MAX_AGE = 60 * 10;

function response(statusCode, body = "", headers = {}) {
  return new Response(body, {
    status: statusCode,
    headers: {
      "Cache-Control": "no-store",
      ...headers,
    },
  });
}

function json(statusCode, data) {
  return response(
    statusCode,
    JSON.stringify(data),
    {
      "Content-Type": "application/json; charset=utf-8",
    }
  );
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function randomToken() {
  return base64url(
    crypto.randomBytes(32)
  );
}

function sign(value) {
  return base64url(
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET || ""
      )
      .update(value)
      .digest()
  );
}

function safeEqual(a, b) {
  try {
    const aBuffer = Buffer.from(a || "");
    const bBuffer = Buffer.from(b || "");

    if (
      aBuffer.length !==
      bBuffer.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      aBuffer,
      bBuffer
    );
  } catch {
    return false;
  }
}

function createSession(email, role) {
  const payload = {
    email,
    role,
    exp:
      Math.floor(Date.now() / 1000) +
      SESSION_MAX_AGE,
  };

  const encoded =
    base64url(
      JSON.stringify(payload)
    );

  const signature =
    sign(encoded);

  return `${encoded}.${signature}`;
}

function parseCookies(header = "") {
  const cookies = {};

  for (
    const item of header.split(";")
  ) {
    const index =
      item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      item
        .slice(0, index)
        .trim();

    const value =
      item
        .slice(index + 1)
        .trim();

    cookies[key] = value;
  }

  return cookies;
}

function getCookie(req, name) {
  const header =
    req.headers.get("cookie") || "";

  const cookies =
    parseCookies(header);

  return cookies[name] || "";
}

function verifySession(
  session,
  expectedRole = null
) {
  try {
    if (
      !session ||
      !SESSION_SECRET
    ) {
      return null;
    }

    const parts =
      session.split(".");

    if (
      parts.length !== 2
    ) {
      return null;
    }

    const encoded =
      parts[0];

    const receivedSignature =
      parts[1];

    const expectedSignature =
      sign(encoded);

    if (
      !safeEqual(
        receivedSignature,
        expectedSignature
      )
    ) {
      return null;
    }

    const payload =
      JSON.parse(
        Buffer.from(
          encoded,
          "base64url"
        ).toString("utf8")
      );

    if (
      !payload ||
      !payload.email ||
      !payload.role ||
      !payload.exp
    ) {
      return null;
    }

    if (
      expectedRole &&
      payload.role !== expectedRole
    ) {
      return null;
    }

    const now =
      Math.floor(
        Date.now() / 1000
      );

    if (
      Number(payload.exp) <= now
    ) {
      return null;
    }

    const email =
      String(
        payload.email
      )
        .trim()
        .toLowerCase();

    if (!email) {
      return null;
    }

    if (
      payload.role === "admin" &&
      email !== ADMIN_EMAIL
    ) {
      return null;
    }

    return {
      email,
      role: payload.role,
      exp: payload.exp,
    };
  } catch (error) {
    console.error(
      "Session verification error:",
      error
    );

    return null;
  }
}

async function getGoogleUser(
  code
) {
  const tokenResponse =
    await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
        },

        body:
          new URLSearchParams({
            client_id: CLIENT_ID,
            client_secret:
              CLIENT_SECRET,
            redirect_uri:
              REDIRECT_URI,
            grant_type:
              "authorization_code",
            code,
          }),
      }
    );

  const tokenData =
    await tokenResponse.json();

  if (
    !tokenResponse.ok ||
    !tokenData.access_token
  ) {
    console.error(
      "Google token request failed:",
      tokenData
    );

    return null;
  }

  const userResponse =
    await fetch(
      "https://openidconnect.googleapis.com/v1/userinfo",
      {
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`,
        },
      }
    );

  const user =
    await userResponse.json();

  if (
    !userResponse.ok ||
    !user.email
  ) {
    console.error(
      "Google userinfo request failed:",
      user
    );

    return null;
  }

  return user;
}

export default async function handler(
  req
) {
  try {
    if (
      !CLIENT_ID ||
      !CLIENT_SECRET ||
      !SESSION_SECRET
    ) {
      return json(500, {
        success: false,
        error:
          "GOOGLE_CLIENT_ID، GOOGLE_CLIENT_SECRET یا SESSION_SECRET تنظیم نشده است.",
      });
    }

    const url =
      new URL(req.url);

    const action =
      url.searchParams.get(
        "action"
      ) || "";

    /*
     * =========================
     * LOGOUT
     * =========================
     */

    if (
      action === "logout"
    ) {
      return response(
        302,
        "",
        {
          "Set-Cookie": [
            "bs_user=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            "bs_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            "bs_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
          ],
          Location: "/",
        }
      );
    }

    /*
     * =========================
     * CHECK USER
     * =========================
     */

    if (
      action === "check"
    ) {
      const userSession =
        getCookie(
          req,
          "bs_user"
        );

      const adminSession =
        getCookie(
          req,
          "bs_admin"
        );

      const user =
        verifySession(
          userSession,
          "user"
        );

      const admin =
        verifySession(
          adminSession,
          "admin"
        );

      if (admin) {
        return json(200, {
          success: true,
          authenticated: true,
          email: admin.email,
          role: "admin",
        });
      }

      if (user) {
        return json(200, {
          success: true,
          authenticated: true,
          email: user.email,
          role: "user",
        });
      }

      return json(401, {
        success: false,
        authenticated: false,
      });
    }

    /*
     * =========================
     * START GOOGLE LOGIN
     * =========================
     */

    const code =
      url.searchParams.get(
        "code"
      );

    if (!code) {
      const state =
        randomToken();

      const googleUrl =
        "https://accounts.google.com/o/oauth2/v2/auth?" +
        new URLSearchParams({
          client_id: CLIENT_ID,
          redirect_uri:
            REDIRECT_URI,
          response_type: "code",
          scope:
            "openid email profile",
          state,
          prompt:
            "select_account",
        }).toString();

      return response(
        302,
        "",
        {
          Location:
            googleUrl,

          "Set-Cookie":
            `bs_oauth_state=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${OAUTH_STATE_MAX_AGE}`,
        }
      );
    }

    /*
     * =========================
     * VERIFY STATE
     * =========================
     */

    const savedState =
      getCookie(
        req,
        "bs_oauth_state"
      );

    const returnedState =
      url.searchParams.get(
        "state"
      ) || "";

    if (
      !savedState ||
      !returnedState ||
      !safeEqual(
        savedState,
        returnedState
      )
    ) {
      return json(403, {
        success: false,
        error:
          "درخواست ورود نامعتبر یا منقضی شده است.",
      });
    }

    /*
     * =========================
     * GOOGLE USER
     * =========================
     */

    const googleUser =
      await getGoogleUser(
        code
      );

    if (!googleUser) {
      return json(401, {
        success: false,
        error:
          "ورود با Google ناموفق بود.",
      });
    }

    const email =
      String(
        googleUser.email || ""
      )
        .trim()
        .toLowerCase();

    if (!email) {
      return json(401, {
        success: false,
        error:
          "ایمیل حساب Google دریافت نشد.",
      });
    }

    /*
     * =========================
     * ADMIN OR USER
     * =========================
     */

    if (
      email === ADMIN_EMAIL
    ) {
      const adminSession =
        createSession(
          email,
          "admin"
        );

      return response(
        302,
        "",
        {
          "Set-Cookie": [
            `bs_admin=${adminSession}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`,
            "bs_user=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            "bs_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
          ],

          Location:
            "/admin.html",
        }
      );
    }

    /*
     * =========================
     * NORMAL CUSTOMER
     * =========================
     */

    const userSession =
      createSession(
        email,
        "user"
      );

    return response(
      302,
      "",
      {
        "Set-Cookie": [
          `bs_user=${userSession}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`,
          "bs_admin=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
          "bs_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
        ],

        Location:
          "/account.html",
      }
    );
  } catch (error) {
    console.error(
      "Bright Star Auth Error:",
      error
    );

    return json(500, {
      success: false,
      error:
        "خطای داخلی سیستم ورود.",
    });
  }
}