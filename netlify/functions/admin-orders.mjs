
import crypto from "crypto";
import { getStore } from "@netlify/blobs";

const ADMIN_EMAIL = (
  process.env.ADMIN_EMAIL ||
  "ghasemiiliya07@gmail.com"
).trim().toLowerCase();

const SESSION_SECRET = process.env.SESSION_SECRET;

function json(statusCode, data) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(data)
  };
}

function parseCookies(header = "") {
  const result = {};

  header.split(";").forEach((item) => {
    const index = item.indexOf("=");

    if (index === -1) return;

    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    result[key] = value;
  });

  return result;
}

function getSession(event) {
  const cookieHeader =
    event.headers?.cookie ||
    event.headers?.Cookie ||
    "";

  const cookies = parseCookies(cookieHeader);

  return cookies.bs_admin || "";
}

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function sign(value) {
  return base64url(
    crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(value)
      .digest()
  );
}

function verifySession(session) {
  try {
    if (!session || !SESSION_SECRET) {
      return null;
    }

    const parts = session.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const encoded = parts[0];
    const receivedSignature = parts[1];

    const expectedSignature = sign(encoded);

    const receivedBuffer =
      Buffer.from(receivedSignature);

    const expectedBuffer =
      Buffer.from(expectedSignature);

    if (
      receivedBuffer.length !==
      expectedBuffer.length
    ) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        receivedBuffer,
        expectedBuffer
      )
    ) {
      return null;
    }

    const payload = JSON.parse(
      Buffer.from(
        encoded,
        "base64url"
      ).toString("utf8")
    );

    if (
      !payload.email ||
      payload.role !== "admin"
    ) {
      return null;
    }

    if (
      String(payload.email)
        .trim()
        .toLowerCase() !== ADMIN_EMAIL
    ) {
      return null;
    }

    if (
      !payload.exp ||
      payload.exp <
        Math.floor(Date.now() / 1000)
    ) {
      return null;
    }

    return payload;
  } catch (error) {
    console.error(
      "Admin session verification error:",
      error
    );

    return null;
  }
}

export async function handler(event) {
  try {
    if (!SESSION_SECRET) {
      return json(500, {
        success: false,
        error:
          "SESSION_SECRET تنظیم نشده است."
      });
    }

    const session = getSession(event);

    const admin = verifySession(session);

    if (!admin) {
      return json(401, {
        success: false,
        error:
          "دسترسی غیرمجاز. ابتدا با حساب مدیر وارد شوید."
      });
    }

    const store =
      getStore("bright-star-orders");

    const result =
      await store.list();

    const orders = [];

    for (const blob of result.blobs || []) {
      try {
        const order =
          await store.get(blob.key, {
            type: "json"
          });

        if (order) {
          orders.push(order);
        }
      } catch (error) {
        console.error(
          "Could not read order:",
          blob.key,
          error
        );
      }
    }

    orders.sort((a, b) => {
      return (
        new Date(b.createdAt || 0) -
        new Date(a.createdAt || 0)
      );
    });

    return json(200, {
      success: true,
      email: admin.email,
      orders
    });
  } catch (error) {
    console.error(
      "Admin Orders Error:",
      error
    );

    return json(500, {
      success: false,
      error:
        "خطای داخلی هنگام دریافت سفارش‌ها."
    });
  }
}
