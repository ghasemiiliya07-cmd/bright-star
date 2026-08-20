import crypto from "crypto";
import { getStore } from "@netlify/blobs";

const CARD_NUMBER = "6219861953495339";

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL ||
  "ghasemiiliya07@gmail.com"
)
  .trim()
  .toLowerCase();

const SESSION_SECRET =
  process.env.SESSION_SECRET;

const SESSION_COOKIE =
  "brightstar_session";

function json(data,status=200){

  return new Response(
    JSON.stringify(data),
    {
      status,
      headers:{
        "Content-Type":
          "application/json; charset=utf-8",

        "Cache-Control":
          "no-store"
      }
    }
  );
}

function normalizeEmail(email){

  return String(email || "")
    .trim()
    .toLowerCase();
}

function generateOrderId(){

  const time =
    Date.now()
      .toString(36)
      .toUpperCase();

  const random =
    Math.random()
      .toString(36)
      .substring(2,7)
      .toUpperCase();

  return `BS-${time}-${random}`;
}

function getProducts(){

  return [
    {
      id:1,
      stars:50,
      price:198603,
      name:"بسته پایه"
    },
    {
      id:2,
      stars:100,
      price:397205,
      name:"بسته کوچک"
    },
    {
      id:3,
      stars:150,
      price:609047,
      name:"بسته ۱۵۰"
    },
    {
      id:4,
      stars:250,
      price:993012,
      name:"بسته ۲۵۰"
    },
    {
      id:5,
      stars:350,
      price:1403457,
      name:"بسته ۳۵۰"
    },
    {
      id:6,
      stars:500,
      price:1986024,
      name:"پیشنهاد ویژه"
    },
    {
      id:7,
      stars:1000,
      price:3972047,
      name:"بسته حرفه‌ای"
    },
    {
      id:8,
      stars:2500,
      price:9930117,
      name:"بسته طلایی"
    },
    {
      id:9,
      stars:5000,
      price:19860234,
      name:"بسته بزرگ"
    },
    {
      id:10,
      stars:10000,
      price:39720466,
      name:"بسته ویژه"
    },
    {
      id:11,
      stars:50000,
      price:198602333,
      name:"بسته ۵۰ هزار"
    },
    {
      id:12,
      stars:25000,
      price:99301167,
      name:"بسته ۲۵ هزار"
    }
  ];
}

function parseCookies(
  cookieHeader=""
){

  const cookies = {};

  for(
    const item of
    cookieHeader.split(";")
  ){

    const index =
      item.indexOf("=");

    if(index === -1){
      continue;
    }

    const key =
      item
        .slice(0,index)
        .trim();

    const value =
      item
        .slice(index + 1)
        .trim();

    try{

      cookies[key] =
        decodeURIComponent(value);

    }catch{

      cookies[key] =
        value;
    }
  }

  return cookies;
}

function base64Url(value){

  return Buffer
    .from(value)
    .toString("base64")
    .replace(/\+/g,"-")
    .replace(/\//g,"_")
    .replace(/=/g,"");
}

function createSignature(value){

  return base64Url(
    crypto
      .createHmac(
        "sha256",
        SESSION_SECRET || ""
      )
      .update(value)
      .digest()
  );
}

function verifySession(request){

  try{

    if(!SESSION_SECRET){
      return null;
    }

    const cookieHeader =
      request.headers.get("cookie") || "";

    const cookies =
      parseCookies(cookieHeader);

    const session =
      cookies[SESSION_COOKIE];

    if(!session){
      return null;
    }

    const parts =
      session.split(".");

    if(parts.length !== 2){
      return null;
    }

    const encodedPayload =
      parts[0];

    const receivedSignature =
      parts[1];

    const expectedSignature =
      createSignature(
        encodedPayload
      );

    const receivedBuffer =
      Buffer.from(
        receivedSignature
      );

    const expectedBuffer =
      Buffer.from(
        expectedSignature
      );

    if(
      receivedBuffer.length !==
      expectedBuffer.length
    ){
      return null;
    }

    if(
      !crypto.timingSafeEqual(
        receivedBuffer,
        expectedBuffer
      )
    ){
      return null;
    }

    const payload =
      JSON.parse(
        Buffer
          .from(
            encodedPayload,
            "base64url"
          )
          .toString("utf8")
      );

    if(
      !payload.email ||
      !payload.exp
    ){
      return null;
    }

    if(
      Number(payload.exp) <
      Math.floor(Date.now()/1000)
    ){
      return null;
    }

    return payload;

  }catch(error){

    console.error(
      "Session verification error:",
      error
    );

    return null;
  }
}

function verifyAdminSession(request){

  const session =
    verifySession(request);

  if(!session){
    return null;
  }

  if(
    session.role !== "admin"
  ){
    return null;
  }

  if(
    normalizeEmail(session.email) !==
    ADMIN_EMAIL
  ){
    return null;
  }

  return session;
}

async function getAllOrders(store){

  const result =
    await store.list();

  const orders = [];

  for(
    const blob of
    result.blobs || []
  ){

    try{

      const order =
        await store.get(
          blob.key,
          {
            type:"json"
          }
        );

      if(order){
        orders.push(order);
      }

    }catch(error){

      console.error(
        "Order read error:",
        blob.key,
        error
      );
    }
  }

  orders.sort(
    (a,b) =>
      new Date(b.createdAt || 0) -
      new Date(a.createdAt || 0)
  );

  return orders;
}

export default async function handler(request){

  try{

    const store =
      getStore(
        "bright-star-orders"
      );

    const url =
      new URL(
        request.url
      );

    /*
     * ==========================
     * ثبت سفارش
     * ==========================
     */

    if(request.method === "POST"){

      const session =
        verifySession(request);

      if(!session){

        return json(
          {
            success:false,
            error:
              "برای ثبت سفارش ابتدا وارد حساب کاربری شوید.",
            authenticated:false
          },
          401
        );
      }

      const body =
        await request.json();

      const {
        productId,
        telegram,
        phone,
        coupon
      } = body;

      if(
        !productId ||
        !telegram ||
        !phone
      ){

        return json(
          {
            success:false,
            error:
              "اطلاعات سفارش کامل نیست."
          },
          400
        );
      }

      const product =
        getProducts().find(
          item =>
            item.id ===
            Number(productId)
        );

      if(!product){

        return json(
          {
            success:false,
            error:
              "بسته انتخاب‌شده معتبر نیست."
          },
          400
        );
      }

      const telegramUsername =
        String(telegram)
          .trim()
          .replace(/^@/,"");

      if(
        telegramUsername.length < 3
      ){

        return json(
          {
            success:false,
            error:
              "آیدی تلگرام معتبر نیست."
          },
          400
        );
      }

      const now =
        new Date().toISOString();

      const orderId =
        generateOrderId();

      const order = {

        id:orderId,

        productId:
          product.id,

        stars:
          product.stars,

        productName:
          product.name,

        amount:
          product.price,

        telegram:
          telegramUsername,

        phone:
          String(phone).trim(),

        name:
          String(
            session.name || ""
          ).trim(),

        email:
          normalizeEmail(
            session.email
          ),

        coupon:
          String(
            coupon || ""
          ).trim(),

        status:
          "pending_payment",

        statusText:
          "در انتظار پرداخت",

        cardNumber:
          CARD_NUMBER,

        createdAt:
          now,

        updatedAt:
          now
      };

      await store.setJSON(
        orderId,
        order
      );

      return json({
        success:true,
        order
      });
    }

    /*
     * ==========================
     * سفارش با ID
     * ==========================
     */

    if(
      request.method === "GET" &&
      url.searchParams.has("id")
    ){

      const session =
        verifySession(request);

      if(!session){

        return json(
          {
            success:false,
            error:"وارد حساب نشده‌اید."
          },
          401
        );
      }

      const orderId =
        url.searchParams.get("id");

      if(!orderId){

        return json(
          {
            success:false,
            error:
              "شناسه سفارش ارسال نشده است."
          },
          400
        );
      }

      const order =
        await store.get(
          orderId,
          {
            type:"json"
          }
        );

      if(!order){

        return json(
          {
            success:false,
            error:
              "سفارش پیدا نشد."
          },
          404
        );
      }

      const isAdmin =
        verifyAdminSession(request);

      const sameUser =
        normalizeEmail(order.email) ===
        normalizeEmail(session.email);

      if(!sameUser && !isAdmin){

        return json(
          {
            success:false,
            error:
              "دسترسی به این سفارش مجاز نیست."
          },
          403
        );
      }

      return json({
        success:true,
        order
      });
    }

    /*
     * ==========================
     * سفارش‌های کاربر
     * ==========================
     */

    if(
      request.method === "GET" &&
      url.searchParams.has("email")
    ){

      return json(
        {
          success:false,
          error:
            "دریافت سفارش با ایمیل غیرفعال شده است. از حساب کاربری استفاده کنید."
        },
        403
      );
    }

    /*
     * ==========================
     * همه سفارش‌ها برای مدیر
     * ==========================
     */

    if(
      request.method === "GET" &&
      url.searchParams.get("admin") === "true"
    ){

      const admin =
        verifyAdminSession(request);

      if(!admin){

        return json(
          {
            success:false,
            error:
              "دسترسی غیرمجاز."
          },
          401
        );
      }

      const orders =
        await getAllOrders(store);

      return json({
        success:true,
        email:
          admin.email,
        orders
      });
    }

    /*
     * ==========================
     * تغییر وضعیت
     * ==========================
     */

    if(
      request.method === "PATCH" ||
      request.method === "PUT"
    ){

      const admin =
        verifyAdminSession(request);

      if(!admin){

        return json(
          {
            success:false,
            error:
              "دسترسی غیرمجاز. فقط مدیر می‌تواند وضعیت سفارش را تغییر دهد."
          },
          401
        );
      }

      const body =
        await request.json();

      const {
        orderId,
        status
      } = body;

      if(
        !orderId ||
        !status
      ){

        return json(
          {
            success:false,
            error:
              "شناسه سفارش یا وضعیت ارسال نشده است."
          },
          400
        );
      }

      const allowedStatuses = {

        pending_payment:
          "در انتظار پرداخت",

        processing:
          "در حال انجام",

        completed:
          "تکمیل شده",

        cancelled:
          "لغو شده"
      };

      if(
        !Object.prototype.hasOwnProperty.call(
          allowedStatuses,
          status
        )
      ){

        return json(
          {
            success:false,
            error:
              "وضعیت سفارش معتبر نیست."
          },
          400
        );
      }

      const order =
        await store.get(
          orderId,
          {
            type:"json"
          }
        );

      if(!order){

        return json(
          {
            success:false,
            error:
              "سفارش پیدا نشد."
          },
          404
        );
      }

      order.status =
        status;

      order.statusText =
        allowedStatuses[status];

      order.updatedAt =
        new Date().toISOString();

      await store.setJSON(
        orderId,
        order
      );

      return json({
        success:true,
        order
      });
    }

    return json(
      {
        success:false,
        error:"Method not allowed"
      },
      405
    );

  }catch(error){

    console.error(
      "Bright Star Orders Error:",
      error
    );

    return json(
      {
        success:false,
        error:
          "خطای داخلی سرور."
      },
      500
    );
  }
}