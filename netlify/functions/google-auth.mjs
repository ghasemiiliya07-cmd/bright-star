
import crypto from "crypto";

const SITE_URL = "https://brightstars.ir";

const REDIRECT_URI =
  "https://brightstars.ir/.netlify/functions/google-auth";

const SESSION_COOKIE = "brightstar_session";
const STATE_COOKIE = "brightstar_oauth_state";

const SESSION_MAX_AGE = 7 * 24 * 60 * 60;
const STATE_MAX_AGE = 10 * 60;

/*
 * ============================
 * Header
 * ============================
 */

function getHeader(event, name) {
  const headers = event.headers || {};
  const wanted = name.toLowerCase();

  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === wanted) {
      return headers[key];
    }
  }

  return undefined;
}

/*
 * ============================
 * Cookies
 * ============================
 */

function parseCookies(event) {
  const header = getHeader(event, "cookie");

  if (!header) {
    return {};
  }

  const result = {};

  for (const item of header.split(";")) {
    const index = item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }

  return result;
}

/*
 * ============================
 * Random Token
 * ============================
 */

function randomToken(bytes = 32) {
  return crypto
    .randomBytes(bytes)
    .toString("hex");
}

/*
 * ============================
 * Base64 URL
 * ============================
 */

function base64UrlEncode(text) {
  return Buffer.from(text, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/*
 * ============================
 * HMAC Signature
 * ============================
 */

function sign(value, secret) {
  return crypto
    .createHmac("sha256", secret)
    .update(value)
    .digest("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/*
 * ============================
 * ساخت Session
 * ============================
 */

function createSession(user, secret) {
  const now =
    Math.floor(Date.now() / 1000);

  const payload = {
    sub: user.sub,
    email: user.email,
    name: user.name || "",
    picture: user.picture || "",
    role: user.role || "user",
    iat: now,
    exp: now + SESSION_MAX_AGE
  };

  const encoded =
    base64UrlEncode(
      JSON.stringify(payload)
    );

  const signature =
    sign(
      encoded,
      secret
    );

  return `${encoded}.${signature}`;
}

/*
 * ============================
 * Session Cookie
 * ============================
 */

function sessionCookie(token) {
  return [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${SESSION_MAX_AGE}`
  ].join("; ");
}

/*
 * ============================
 * OAuth State Cookie
 * ============================
 */

function stateCookie(state) {
  return [
    `${STATE_COOKIE}=${encodeURIComponent(state)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${STATE_MAX_AGE}`
  ].join("; ");
}

/*
 * ============================
 * پاک کردن State Cookie
 * ============================
 */

function clearStateCookie() {
  return [
    `${STATE_COOKIE}=`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    "Max-Age=0"
  ].join("; ");
}

/*
 * ============================
 * Redirect
 * ============================
 */

function redirect(
  location,
  cookies = []
) {
  return {
    statusCode: 302,

    headers: {
      Location: location,
      "Cache-Control": "no-store"
    },

    multiValueHeaders: {
      "Set-Cookie": cookies
    },

    body: ""
  };
}

/*
 * ============================
 * Handler
 * ============================
 */

export const handler =
  async (event) => {

    try {

      /*
       * ============================
       * Environment Variables
       * ============================
       */

      const clientId =
        process.env.GOOGLE_CLIENT_ID;

      const clientSecret =
        process.env.GOOGLE_CLIENT_SECRET;

      const adminEmail =
        String(
          process.env.ADMIN_EMAIL || ""
        )
          .trim()
          .toLowerCase();

      const sessionSecret =
        process.env.SESSION_SECRET;

      /*
       * ============================
       * بررسی تنظیمات
       * ============================
       */

      if (!clientId) {

        console.error(
          "GOOGLE_CLIENT_ID is missing."
        );

        return redirect(
          `${SITE_URL}/account.html?login=config_error`
        );
      }

      if (!clientSecret) {

        console.error(
          "GOOGLE_CLIENT_SECRET is missing."
        );

        return redirect(
          `${SITE_URL}/account.html?login=config_error`
        );
      }

      if (!adminEmail) {

        console.error(
          "ADMIN_EMAIL is missing."
        );

        return redirect(
          `${SITE_URL}/account.html?login=config_error`
        );
      }

      if (!sessionSecret) {

        console.error(
          "SESSION_SECRET is missing."
        );

        return redirect(
          `${SITE_URL}/account.html?login=config_error`
        );
      }

      /*
       * ============================
       * Query Parameters
       * ============================
       */

      const query =
        event.queryStringParameters || {};

      const code =
        query.code;

      const returnedState =
        query.state;

      const googleError =
        query.error;

      /*
       * ============================
       * لغو ورود توسط کاربر
       * ============================
       */

      if (googleError) {

        console.log(
          "Google login cancelled:",
          googleError
        );

        return redirect(
          `${SITE_URL}/account.html?login=cancelled`,
          [
            clearStateCookie()
          ]
        );
      }

      /*
       * ============================
       * شروع ورود با Google
       * ============================
       */

      if (!code) {

        const state =
          randomToken(32);

        const params =
          new URLSearchParams();

        params.set(
          "client_id",
          clientId
        );

        params.set(
          "redirect_uri",
          REDIRECT_URI
        );

        params.set(
          "response_type",
          "code"
        );

        params.set(
          "scope",
          "openid email profile"
        );

        params.set(
          "access_type",
          "online"
        );

        params.set(
          "prompt",
          "select_account"
        );

        params.set(
          "state",
          state
        );

        const googleUrl =
          "https://accounts.google.com/o/oauth2/v2/auth?" +
          params.toString();

        return redirect(
          googleUrl,
          [
            stateCookie(state)
          ]
        );
      }

      /*
       * ============================
       * بررسی State
       * ============================
       */

      const cookies =
        parseCookies(event);

      const savedState =
        cookies[STATE_COOKIE];

      if (
        !savedState ||
        !returnedState ||
        savedState !== returnedState
      ) {

        console.error(
          "OAuth state mismatch."
        );

        return redirect(
          `${SITE_URL}/account.html?login=state_error`,
          [
            clearStateCookie()
          ]
        );
      }

      /*
       * ============================
       * دریافت Access Token
       * ============================
       */

      const tokenResponse =
        await fetch(
          "https://oauth2.googleapis.com/token",
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/x-www-form-urlencoded"
            },

            body:
              new URLSearchParams({
                code: code,
                client_id: clientId,
                client_secret:
                  clientSecret,
                redirect_uri:
                  REDIRECT_URI,
                grant_type:
                  "authorization_code"
              })
          }
        );

      const tokenData =
        await tokenResponse.json();

      if (
        !tokenResponse.ok ||
        !tokenData.access_token
      ) {

        console.error(
          "Google token exchange failed.",
          tokenData
        );

        return redirect(
          `${SITE_URL}/account.html?login=token_error`,
          [
            clearStateCookie()
          ]
        );
      }

      /*
       * ============================
       * دریافت اطلاعات کاربر
       * ============================
       */

      const userResponse =
        await fetch(
          "https://openidconnect.googleapis.com/v1/userinfo",
          {
            method: "GET",

            headers: {
              Authorization:
                `Bearer ${tokenData.access_token}`
            }
          }
        );

      const user =
        await userResponse.json();

      if (
        !userResponse.ok ||
        !user.email ||
        !user.sub
      ) {

        console.error(
          "Google user information failed.",
          user
        );

        return redirect(
          `${SITE_URL}/account.html?login=user_error`,
          [
            clearStateCookie()
          ]
        );
      }

      /*
       * ============================
       * Email
       * ============================
       */

      const email =
        String(user.email)
          .trim()
          .toLowerCase();

      /*
       * ============================
       * تشخیص نقش کاربر
       * ============================
       */

      const role =
        email === adminEmail
          ? "admin"
          : "user";

      console.log(
        "Google login successful."
      );

      console.log(
        "Logged in email:",
        email
      );

      console.log(
        "User role:",
        role
      );

      /*
       * ============================
       * ساخت Session
       * ============================
       */

      const session =
        createSession(
          {
            sub:
              user.sub,

            email:
              email,

            name:
              user.name || "",

            picture:
              user.picture || "",

            role:
              role
          },
          sessionSecret
        );

      /*
       * ============================
       * ورود موفق
       * ============================
       */

      return redirect(
        `${SITE_URL}/account.html?login=success`,
        [
          sessionCookie(session),
          clearStateCookie()
        ]
      );

    } catch (error) {

      console.error(
        "Google OAuth error:",
        error
      );

      return redirect(
        `${SITE_URL}/account.html?login=failed`
      );
    }
  };

