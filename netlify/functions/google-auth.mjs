export const handler = async (event) => {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

  console.log("Google Client ID exists:", Boolean(clientId));
  console.log("Google Client Secret exists:", Boolean(clientSecret));

  if (!clientId || !clientSecret) {
    return {
      statusCode: 500,
      body: "Google OAuth environment variables are missing."
    };
  }

  const siteUrl = "https://brightstars.ir";
  const redirectUri = `${siteUrl}/.netlify/functions/google-auth`;

  const params = new URLSearchParams(
    event.queryStringParameters || {}
  );

  // شروع ورود با Google
  if (!params.get("code")) {
    const googleUrl = new URL(
      "https://accounts.google.com/o/oauth2/v2/auth"
    );

    googleUrl.searchParams.set("client_id", clientId);
    googleUrl.searchParams.set("redirect_uri", redirectUri);
    googleUrl.searchParams.set("response_type", "code");
    googleUrl.searchParams.set("scope", "openid email profile");
    googleUrl.searchParams.set("access_type", "online");
    googleUrl.searchParams.set("prompt", "select_account");

    return {
      statusCode: 302,
      headers: {
        Location: googleUrl.toString()
      }
    };
  }

  // دریافت کد از Google
  const code = params.get("code");

  const tokenResponse = await fetch(
    "https://oauth2.googleapis.com/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: "authorization_code"
      })
    }
  );

  const tokenData = await tokenResponse.json();

  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Google token error:", tokenData);

    return {
      statusCode: 401,
      body: "Google login failed."
    };
  }

  // دریافت اطلاعات کاربر
  const userResponse = await fetch(
    "https://openidconnect.googleapis.com/v1/userinfo",
    {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`
      }
    }
  );

  const user = await userResponse.json();

  if (!userResponse.ok) {
    return {
      statusCode: 401,
      body: "Could not retrieve Google account."
    };
  }

  console.log("Google login successful:", user.email);

  // برگشت به صفحه حساب
  const accountUrl = new URL(
    "/account.html",
    siteUrl
  );

  accountUrl.searchParams.set("google_login", "success");
  accountUrl.searchParams.set("name", user.name || "");
  accountUrl.searchParams.set("email", user.email || "");
  accountUrl.searchParams.set("picture", user.picture || "");

  return {
    statusCode: 302,
    headers: {
      Location: accountUrl.toString()
    }
  };
};