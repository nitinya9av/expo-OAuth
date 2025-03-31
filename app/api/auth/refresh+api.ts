import * as jose from "jose";
import {
  JWT_EXPIRATION_TIME,
  JWT_SECRET,
  REFRESH_TOKEN_EXPIRY,
} from "@/utils/constants";

/**
 * Refresh API endpoint
 *
 * This endpoint refreshes the user's authentication token using a refresh token.
 * It implements token rotation - each refresh generates a new refresh token.
 * For web clients, it refreshes the cookies.
 * For native clients, it returns new tokens.
 */
export async function POST(request: Request) {
  try {
    let refreshToken: string | null = null;

    // Check content type to determine how to parse the body
    const contentType = request.headers.get("content-type") || "";

    if (contentType.includes("application/json")) {
      // Handle JSON body
      try {
        const jsonBody = await request.json();
        // For native clients, get refresh token from request body
        if (jsonBody.refreshToken) {
          refreshToken = jsonBody.refreshToken;
        }
      } catch (e) {
        console.log("Failed to parse JSON body, using default platform");
      }
    } else if (
      contentType.includes("application/x-www-form-urlencoded") ||
      contentType.includes("multipart/form-data")
    ) {
      // Handle form data
      try {
        const formData = await request.formData();
          refreshToken = formData.get("refreshToken") as string;
      } catch (e) {
        console.log("Failed to parse form data, using default platform");
      }
    } else {
      // For other content types or no content type, check URL parameters
      try {
        const url = new URL(request.url);
      } catch (e) {
        console.log("Failed to parse URL parameters, using default platform");
      }
    }

    // If no refresh token found, try to use the access token as fallback
    if (!refreshToken) {
      // For native clients, get access token from Authorization header
      const authHeader = request.headers.get("authorization");
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const accessToken = authHeader.split(" ")[1];

        try {
          // Verify the access token
          const decoded = await jose.jwtVerify(
            accessToken,
            new TextEncoder().encode(JWT_SECRET)
          );

          // If token is still valid, use it to create a new token
          // This is a fallback mechanism and not ideal for security
          console.log("No refresh token found, using access token as fallback");

          // Get the user info from the token
          const userInfo = decoded.payload;

          // Current timestamp in seconds
          const issuedAt = Math.floor(Date.now() / 1000);

          // Create a new access token
          const newAccessToken = await new jose.SignJWT({ ...userInfo })
            .setProtectedHeader({ alg: "HS256" })
            .setExpirationTime(JWT_EXPIRATION_TIME)
            .setSubject(userInfo.sub as string)
            .setIssuedAt(issuedAt)
            .sign(new TextEncoder().encode(JWT_SECRET));

          // For native platforms
          return Response.json({
            accessToken: newAccessToken,
            warning: "Using access token fallback - refresh token missing",
          });
        } catch (error) {
          // Access token is invalid or expired
          return Response.json(
            { error: "Authentication required - no valid refresh token" },
            { status: 401 }
          );
        }
      }

      return Response.json(
        { error: "Authentication required - no refresh token" },
        { status: 401 }
      );
    }

    // Verify the refresh token
    let decoded;
    try {
      decoded = await jose.jwtVerify(
        refreshToken,
        new TextEncoder().encode(JWT_SECRET)
      );
    } catch (error) {
      if (error instanceof jose.errors.JWTExpired) {
        return Response.json(
          { error: "Refresh token expired, please sign in again" },
          { status: 401 }
        );
      } else {
        return Response.json(
          { error: "Invalid refresh token, please sign in again" },
          { status: 401 }
        );
      }
    }

    // Verify this is actually a refresh token
    const payload = decoded.payload;
    if (payload.type !== "refresh") {
      return Response.json(
        { error: "Invalid token type, please sign in again" },
        { status: 401 }
      );
    }

    // Get the subject (user ID) from the token
    const sub = payload.sub;
    if (!sub) {
      return Response.json(
        { error: "Invalid token, missing subject" },
        { status: 401 }
      );
    }

    // Current timestamp in seconds
    const issuedAt = Math.floor(Date.now() / 1000);

    // Generate a unique jti (JWT ID) for the new refresh token
    const jti = crypto.randomUUID();

    // Get the user info from the token
    const userInfo = decoded.payload;

    // Check if we have all the required user information
    // If not, we need to add it to ensure ProfileCard works correctly
    const hasRequiredUserInfo =
      userInfo.name && userInfo.email && userInfo.picture;

    // Create a complete user info object
    let completeUserInfo = { ...userInfo };

    // If we're missing user info, try to fetch it from a user database or service
    // For this example, we'll just ensure the type field is preserved
    if (!hasRequiredUserInfo) {
      // In a real implementation, you would fetch the user data from your database
      // using the sub (user ID) as the key
      // For now, we'll just ensure we keep the refresh token type
      completeUserInfo = {
        ...userInfo,
        // Preserve the refresh token type
        type: "refresh",
        // Add any missing fields that might be needed by the UI
        // These would normally come from your user database
        name: userInfo.name || `User ${sub.substring(0, 6)}`,
        email: userInfo.email || `user-${sub.substring(0, 6)}@example.com`,
        picture:
          userInfo.picture ||
          `https://ui-avatars.com/api/?name=User&background=random`,
      };
    }

    // Create a new access token with complete user info
    const newAccessToken = await new jose.SignJWT({
      ...completeUserInfo,
      // Remove the refresh token specific fields from the access token
      type: undefined,
    })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime(JWT_EXPIRATION_TIME)
      .setSubject(sub)
      .setIssuedAt(issuedAt)
      .sign(new TextEncoder().encode(JWT_SECRET));

    // Create a new refresh token (token rotation)
    const newRefreshToken = await new jose.SignJWT({
      ...completeUserInfo,
      jti,
      type: "refresh",
    })
      .setProtectedHeader({ alg: "HS256" })
      .setExpirationTime(REFRESH_TOKEN_EXPIRY)
      .setIssuedAt(issuedAt)
      .sign(new TextEncoder().encode(JWT_SECRET));

    // For native platforms, return the new tokens in the response body
    return Response.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    return Response.json({ error: "Failed to refresh token" }, { status: 500 });
  }
}
