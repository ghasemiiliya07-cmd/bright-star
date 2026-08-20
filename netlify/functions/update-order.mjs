
import crypto from "crypto";
import { getStore } from "@netlify/blobs";

const ADMIN_EMAIL = (
  process.env.ADMIN_EMAIL ||
  "ghasemiiliya07@gmail.com"
)
  .trim()
  .toLowerCase();

const SESSION_SECRET = process.env.SESSION_SECRET;

const STORE_NAME = "bright-star-orders";

const ALLOWED_STATUSES = {
  pending_payment: "در انتظار پرداخت",
  processing: "در حال انجام",
  completed: "تکمیل شده",
  cancelled: "لغو شده",
};

/*
 * ============================
 * پاسخ JSON
 * ============================
 */

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        "Content-Type":
          "application/json; charset=utf-8",
        "Cache-Control": "no-store",
      },
    }
  );
}

/*
 * ============================
 * خواندن Cookie
 * ============================
 */

function parseCookies(cookieHeader = "") {
  const cookies = {};

  cookieHeader
    .split(";")
    .forEach((part) => {
      const index = part.indexOf("=");

      if (index === -1) {
        return;
      }

      const key = part
        .slice(0, index)
        .trim();

      const value = part
        .slice(index + 1)
        .trim();

      cookies[key] = value;
    });

  return cookies;
}

/*
 * ============================
 * گرفتن Session مدیر
 * ============================
 */

function getAdminSession(req) {
  const cookieHeader =
    req.headers.get("cookie") || "";

  const cookies =
    parseCookies(cookieHeader);

  return cookies.bs_admin || "";
}

/*
 * ============================
 * Base64 URL
 * ============================
 */

function base64url(value) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

/*
 * ============================
 * امضای Session
 * ============================
 */

function sign(value) {
  if (!SESSION_SECRET) {
    return "";
  }

  return base64url(
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET
      )
      .update(value)
      .digest()
  );
}

/*
 * ============================
 * بررسی Session
 * ============================
 */

function verifySession(session) {
  try {
    if (!session || !SESSION_SECRET) {
      return null;
    }

    const parts =
      session.split(".");

    if (parts.length !== 2) {
      return null;
    }

    const encoded = parts[0];

    const receivedSignature =
      parts[1];

    const expectedSignature =
      sign(encoded);

    if (
      !receivedSignature ||
      !expectedSignature
    ) {
      return null;
    }

    const receivedBuffer =
      Buffer.from(
        receivedSignature
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature
      );

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
      payload.role !== "admin"
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

    const email =
      String(payload.email)
        .trim()
        .toLowerCase();

    if (email !== ADMIN_EMAIL) {
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

/*
 * ============================
 * Handler
 * ============================
 */

export default async function handler(req) {
  try {
    /*
     * فقط PATCH و PUT
     */

    if (
      req.method !== "PATCH" &&
      req.method !== "PUT"
    ) {
      return json(
        {
          success: false,
          error:
            "Method not allowed",
        },
        405
      );
    }

    /*
     * بررسی تنظیمات امنیتی
     */

    if (!SESSION_SECRET) {
      console.error(
        "SESSION_SECRET is missing"
      );

      return json(
        {
          success: false,
          error:
            "تنظیمات امنیتی سرور کامل نیست.",
        },
        500
      );
    }

    /*
     * بررسی Session مدیر
     */

    const session =
      getAdminSession(req);

    const admin =
      verifySession(session);

    if (!admin) {
      return json(
        {
          success: false,
          error:
            "دسترسی غیرمجاز. ابتدا وارد پنل مدیریت شوید.",
        },
        401
      );
    }

    /*
     * دریافت اطلاعات درخواست
     */

    let body;

    try {
      body = await req.json();
    } catch {
      return json(
        {
          success: false,
          error:
            "اطلاعات ارسال‌شده معتبر نیست.",
        },
        400
      );
    }

    const orderId =
      String(
        body?.orderId ||
        body?.id ||
        ""
      ).trim();

    const status =
      String(
        body?.status ||
        ""
      ).trim();

    /*
     * بررسی اطلاعات
     */

    if (!orderId || !status) {
      return json(
        {
          success: false,
          error:
            "شناسه سفارش و وضعیت جدید الزامی است.",
        },
        400
      );
    }

    /*
     * بررسی وضعیت مجاز
     */

    if (
      !Object.prototype.hasOwnProperty.call(
        ALLOWED_STATUSES,
        status
      )
    ) {
      return json(
        {
          success: false,
          error:
            "وضعیت سفارش معتبر نیست.",
          allowedStatuses:
            ALLOWED_STATUSES,
        },
        400
      );
    }

    /*
     * اتصال به Netlify Blobs
     */

    const store =
      getStore(STORE_NAME);

    /*
     * دریافت سفارش
     */

    const order =
      await store.get(
        orderId,
        {
          type: "json",
        }
      );

    if (!order) {
      return json(
        {
          success: false,
          error:
            "سفارش پیدا نشد.",
        },
        404
      );
    }

    /*
     * وضعیت قبلی
     */

    const previousStatus =
      order.status || "";

    /*
     * تغییر وضعیت
     */

    order.status = status;

    order.statusText =
      ALLOWED_STATUSES[status];

    order.updatedAt =
      new Date().toISOString();

    /*
     * ثبت اطلاعات آخرین تغییر
     */

    order.lastUpdatedBy =
      admin.email;

    order.previousStatus =
      previousStatus;

    /*
     * ذخیره سفارش
     */

    await store.setJSON(
      orderId,
      order
    );

    console.log(
      `Order ${orderId} status changed from ${previousStatus} to ${status} by ${admin.email}`
    );

    /*
     * پاسخ موفق
     */

    return json({
      success: true,

      message:
        "وضعیت سفارش با موفقیت تغییر کرد.",

      order,
    });
  } catch (error) {
    console.error(
      "Update Order Error:",
      error
    );

    return json(
      {
        success: false,
        error:
          "خطای داخلی سرور هنگام تغییر وضعیت سفارش.",
      },
      500
    );
  }
}