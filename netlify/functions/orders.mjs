import { getStore } from "@netlify/blobs";

const CARD_NUMBER = "6219861953495339";

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function generateOrderId() {
  const time = Date.now().toString(36).toUpperCase();
  const random = Math.random()
    .toString(36)
    .substring(2, 7)
    .toUpperCase();

  return `BS-${time}-${random}`;
}

export default async function handler(req) {

  try {

    const store = getStore("bright-star-orders");

    /* ثبت سفارش */

    if (req.method === "POST") {

      const body = await req.json();

      const {
        productId,
        telegram,
        phone,
        coupon
      } = body;

      if (!productId || !telegram || !phone) {

        return json({
          success: false,
          error: "اطلاعات سفارش کامل نیست."
        },400);

      }

      const orderId =
        generateOrderId();

      const order = {

        id: orderId,

        productId:
          Number(productId),

        telegram:
          String(telegram)
            .replace(/^@/, ""),

        phone:
          String(phone),

        coupon:
          coupon || "",

        status:
          "pending_payment",

        statusText:
          "در انتظار پرداخت",

        cardNumber:
          CARD_NUMBER,

        createdAt:
          new Date().toISOString()

      };

      await store.setJSON(
        orderId,
        order
      );

      return json({

        success:true,

        order:order

      });
    }

    /* دریافت یک سفارش */

    if (req.method === "GET") {

      const url =
        new URL(req.url);

      const orderId =
        url.searchParams.get("id");

      if (!orderId) {

        return json({
          success:false,
          error:"شناسه سفارش ارسال نشده است."
        },400);

      }

      const order =
        await store.get(orderId,{
          type:"json"
        });

      if (!order) {

        return json({
          success:false,
          error:"سفارش پیدا نشد."
        },404);

      }

      return json({

        success:true,

        order:order

      });

    }

    return json({

      success:false,

      error:"Method not allowed"

    },405);

  } catch(error) {

    console.error(
      "Bright Star Orders Error:",
      error
    );

    return json({

      success:false,

      error:"خطای داخلی سرور"

    },500);

  }

}