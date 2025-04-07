import * as jose from "jose";
import {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
  DJANGO_AUTH_URL,
  DJANGO_CLIENT_ID,
  DJANGO_CLIENT_SECRET,
  JWT_EXPIRATION_TIME,
  JWT_SECRET,
  REFRESH_TOKEN_EXPIRY,
} from "@/utils/constants";

export async function POST(request: Request) {
  const body = await request.formData();
  const code = body.get("code") as string;

  if (!code) {
    return Response.json(
      { error: "Missing authorization code" },
      { status: 400 }
    );
  }

  const response = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI,
      grant_type: "authorization_code",
      code: code,
    }),
  });

  const data = await response.json();

  if (!data.id_token) {
    return Response.json(
      { error: "Missing required parameters" },
      { status: 400 }
    );
  }

  // Fetch access and refresh tokens from Django backend
  const djangoResponse = await fetch(DJANGO_AUTH_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      backend: "google-identity",
      grant_type: "convert_token",
      client_id: DJANGO_CLIENT_ID,
      client_secret: DJANGO_CLIENT_SECRET,
      token: data.id_token,
    }),
  });

  const djangoData = await djangoResponse.json();

  if (!djangoResponse.ok) {
    return Response.json(
      {
        error: djangoData.error || "Failed to convert token",
        message: djangoData.error_description || "An error occurred while converting the token",
      },
      { status: djangoResponse.status }
    );
  }

  const apiAccessToken = djangoData.access_token
  const apiRefreshToken = djangoData.refresh_token
  const apiExpiryTime = djangoData.expires_in

  const userInfo = jose.decodeJwt(data.id_token) as object;

  // Create a new object without the exp property from the original token
  const { exp, ...userInfoWithoutExp } = userInfo as any;

  // User id
  const sub = (userInfo as { sub: string }).sub;

  // Current timestamp in seconds
  const issuedAt = Math.floor(Date.now() / 1000);

  // Generate a unique jti (JWT ID) for the refresh token
  const jti = crypto.randomUUID();

  // Create access token (short-lived)
  const accessToken = await new jose.SignJWT(userInfoWithoutExp)
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(JWT_EXPIRATION_TIME)
    .setSubject(sub)
    .setIssuedAt(issuedAt)
    .sign(new TextEncoder().encode(JWT_SECRET));

  // Create refresh token (long-lived)
  const refreshToken = await new jose.SignJWT({
    sub,
    jti, // Include a unique ID for this refresh token
    type: "refresh",
    // Include all user information in the refresh token
    // This ensures we have the data when refreshing tokens
    name: (userInfo as any).name,
    email: (userInfo as any).email,
    picture: (userInfo as any).picture,
    given_name: (userInfo as any).given_name,
    family_name: (userInfo as any).family_name,
    email_verified: (userInfo as any).email_verified,
  })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime(REFRESH_TOKEN_EXPIRY)
    .setIssuedAt(issuedAt)
    .sign(new TextEncoder().encode(JWT_SECRET));

  if (data.error) {
    return Response.json(
      {
        error: data.error,
        error_description: data.error_description,
        message:
          "OAuth validation error - please ensure the app complies with Google's OAuth 2.0 policy",
      },
      {
        status: 400,
      }
    );
  }

  // For native platforms, return both tokens in the response body
  return Response.json({
    accessToken,
    refreshToken,
    apiAccessToken,
    apiRefreshToken,
    apiExpiryTime,
  });
}
