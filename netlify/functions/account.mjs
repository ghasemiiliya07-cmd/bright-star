import crypto from "crypto";
import { getStore } from "@netlify/blobs";

const SESSION_COOKIE = "brightstar_session";

function json(data, status = 200){

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

function parseCookies(header = ""){

  const cookies = {};

  for(
    const item of header.split(";")
  ){

    const index =
      item.indexOf("=");

    if(index === -1){
      continue;
    }

    const key =
      item.slice(0,index).trim();

    const value =
      item.slice(index + 1).trim();

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

function createSignature(value, secret){

  return base64Url(
    crypto
      .createHmac(
        "sha256",
        secret
      )
      .update(value)
      .digest()
  );
}

function verifySession(request){

  try{

    const secret =
      process.env.SESSION_SECRET;

    if(!secret){
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

    const encoded =
      parts[0];

    const received =
      parts[1];

    const expected =
      createSignature(
        encoded,
        secret
      );

    const receivedBuffer =
      Buffer.from(received);

    const expectedBuffer =
      Buffer.from(expected);

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
            encoded,
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
      Math.floor(Date.now() / 1000)
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

async function getAllOrders(store){

  const result =
    await store.list();

  const orders = [];

  for(
    const blob of result.blobs || []
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

    if(request.method !== "GET"){

      return json(
        {
          success:false,
          error:"Method not allowed"
        },
        405
      );
    }

    const session =
      verifySession(request);

    if(!session){

      return json(
        {
          success:false,
          authenticated:false,
          error:"وارد حساب کاربری نشده‌اید."
        },
        401
      );
    }

    const email =
      normalizeEmail(
        session.email
      );

    const store =
      getStore(
        "bright-star-orders"
      );

    const allOrders =
      await getAllOrders(store);

    const orders =
      allOrders.filter(
        order =>
          normalizeEmail(
            order.email
          ) === email
      );

    return json({
      success:true,
      authenticated:true,

      user:{
        email:email,
        name:session.name || "",
        picture:session.picture || "",
        role:session.role || "user"
      },

      orders
    });

  }catch(error){

    console.error(
      "Bright Star Account Error:",
      error
    );

    return json(
      {
        success:false,
        authenticated:false,
        error:"خطای داخلی سرور."
      },
      500
    );
  }
}