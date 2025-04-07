import {
  DJANGO_CLIENT_ID,
  DJANGO_CLIENT_SECRET,
} from "@/utils/constants";

export async function POST(request: Request) {
  try {
    const body = await request.json();
    const apiRefreshToken = body.apiRefreshToken;

    if (!apiRefreshToken) {
      return Response.json(
        { error: "Missing API refresh token" },
        { status: 400 }
      );
    }

    // Call Django server to refresh the API access token
    const djangoResponse = await fetch('https://dev.backend.iitmparadox.org/auth/token', {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        backend: "google-identity",
        grant_type: "refresh_token",
        client_id: DJANGO_CLIENT_ID,
        client_secret: DJANGO_CLIENT_SECRET,
        refresh_token: apiRefreshToken,
      }),
    });

    const djangoData = await djangoResponse.json();

    if (!djangoResponse.ok) {
      return Response.json(
        {
          error: djangoData.error || "Failed to refresh token",
          message:
            djangoData.error_description ||
            "An error occurred while refreshing the token",
        },
        { status: djangoResponse.status }
      );
    }

    return Response.json({
      apiAccessToken: djangoData.access_token,
      apiRefreshToken: djangoData.refresh_token,
      apiExpiryTime: djangoData.expires_in,
    });
  } catch (error) {
    console.error("Error refreshing API token:", error);
    return Response.json(
      { error: "Failed to refresh API token" },
      { status: 500 }
    );
  }
}
