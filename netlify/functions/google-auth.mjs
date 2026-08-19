export const handler = async (event) => {
  try {
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

    // بررسی امن متغیرها، بدون نمایش مقدار Secret
    console.log(
      "GOOGLE_CLIENT_ID:",
      clientId ? "FOUND" : "MISSING"
    );

    console.log(
      "GOOGLE_CLIENT_SECRET:",
      clientSecret ? "FOUND" : "MISSING"
    );

    // اگر متغیرها وجود نداشته باشند
    if (!clientId || !clientSecret) {
      return {
        statusCode: 500,
        headers: {
          "Content-Type": "text/plain; charset=utf-8"
        },
        body:
          "Google OAuth configuration error: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET is missing."
      };
    }

    const siteUrl = "https://brightstars.ir";
    const redirectUri =
      "https://brightstars.ir/.netlify/functions/google-auth";

    const query = event.queryStringParameters || {};
    const code = query.code;

    /*
     * مرحله ۱:
     * کاربر وارد Google می‌شود
     */
    if (!code) {
      const googleAuthUrl =
        "https://accounts.google.com/o/oauth2/v2/auth?" +
        new URLSearchParams({
          client_id: clientId,
          redirect_uri: redirectUri,
          response_type: "code",
          scope: "openid email profile",
          access_type: "online",
          prompt: "select_account"
        }).toString();

      return {
        statusCode: 302,
        headers: {
          Location: googleAuthUrl,
          "Cache-Control": "no-store"
        },
        body: ""
      };
    }

    /*
     * مرحله ۲:
     * تبدیل Authorization Code به Access Token
     */
    const tokenResponse = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          code: code,
          client_id: clientId,
          client_secret: clientSecret,
          redirect_uri: redirectUri,
          grant_type: "authorization_code"
        })
      }
    );

    const tokenData = await tokenResponse.json();

    if (
      !tokenResponse.ok ||
      !tokenData.access_token
    ) {
      console.error(
        "Google token request failed:",
        tokenData
      );

      return {
        statusCode: 401,
        headers: {
          "Content-Type":
            "text/plain; charset=utf-8"
        },
        body:
          "Google authentication failed while requesting token."
      };
    }

    /*
     * مرحله ۳:
     * دریافت اطلاعات حساب Google
     */
    const userResponse = await fetch(
      "https://openidconnect.googleapis.com/v1/userinfo",
      {
        method: "GET",
        headers: {
          Authorization:
            `Bearer ${tokenData.access_token}`
        }
      }
    );

    const user = await userResponse.json();

    if (!userResponse.ok || !user.email) {
      console.error(
        "Google userinfo request failed:",
        user
      );

      return {
        statusCode: 401,
        headers: {
          "Content-Type":
            "text/plain; charset=utf-8"
        },
        body:
          "Could not retrieve Google account information."
      };
    }

    console.log(
      "Google login successful:",
      user.email
    );

    /*
     * مرحله ۴:
     * انتقال کاربر به صفحه حساب Bright Star
     */
    const accountUrl =
      new URL(
        "/account.html",
        siteUrl
      );

    accountUrl.searchParams.set(
      "google_login",
      "success"
    );

    accountUrl.searchParams.set(
      "name",
      user.name || ""
    );

    accountUrl.searchParams.set(
      "email",
      user.email || ""
    );

    accountUrl.searchParams.set(
      "picture",
      user.picture || ""
    );

    return {
      statusCode: 302,
      headers: {
        Location: accountUrl.toString(),
        "Cache-Control": "no-store"
      },
      body: ""
    };

  } catch (error) {
    console.error(
      "Google OAuth unexpected error:",
      error
    );

    return {
      statusCode: 500,
      headers: {
        "Content-Type":
          "text/plain; charset=utf-8"
      },
      body:
        "An unexpected error occurred during Google login."
    };
  }
};