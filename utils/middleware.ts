import * as jose from "jose";
import { JWT_SECRET } from "@/utils/constants";

export type AuthUser = {
  id: string;
  email: string;
  name: string;
  picture?: string;
  given_name?: string;
  family_name?: string;
  email_verified?: boolean;
  provider?: string;
  exp?: number;
};

/**
 * Middleware to authenticate API requests using JWT from Authorization header
 * @param handler The API route handler to be protected
 *
 * Note for devs: This function acts as a higher-order function that adds authentication to API route handlers.
 */
export function withAuth<T extends Response>(
  handler: (req: Request, user: AuthUser) => Promise<T>
) {
  return async (req: Request): Promise<T | Response> => {
    try {
      let token: string | null = null;

      // Get token from Authorization header (for native apps)
      const authHeader = req.headers.get("authorization");
      if (authHeader && authHeader.startsWith("Bearer ")) {
        token = authHeader.split(" ")[1];
      }

      // If no token found, return unauthorized
      if (!token) {
        return Response.json(
          { error: "Authentication required" },
          { status: 401 }
        );
      }

      // Verify the JWT token
      const jwtSecret = JWT_SECRET;

      if (!jwtSecret) {
        return Response.json(
          { error: "Server misconfiguration" },
          { status: 500 }
        );
      }

      // Verify and decode the token
      const decoded = await jose.jwtVerify(
        token,
        new TextEncoder().encode(jwtSecret) // jose requires you to encode the secret key manually
      );

      // Call the handler with the authenticated user
      return await handler(req, decoded.payload as AuthUser);
    } catch (error) {
      if (error instanceof jose.errors.JWTExpired) {
        console.error("Token expired:", error.reason);
        return Response.json({ error: "Token expired" }, { status: 401 });
      } else if (error instanceof jose.errors.JWTInvalid) {
        console.error("Invalid token:", error.message);
        return Response.json({ error: "Invalid token" }, { status: 401 });
      } else {
        console.error("Auth error:", error);
        return Response.json(
          { error: "Authentication failed" },
          { status: 500 }
        );
      }
    }
  };
}