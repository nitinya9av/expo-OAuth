import { APP_SCHEME } from "@/utils/constants";

export async function GET(request: Request) {
  const incomingParams = new URLSearchParams(request.url.split("?")[1]);
  const combinedPlatformAndState = incomingParams.get("state");
  if (!combinedPlatformAndState) {
    return Response.json({ error: "Invalid state" }, { status: 400 });
  }
  // Extract the state from the combined platform and state
  const state = combinedPlatformAndState.split("|")[1];

  const outgoingParams = new URLSearchParams({
    code: incomingParams.get("code")?.toString() || "",
    state,
  });

  // Always use the mobile app scheme for redirection
  const redirectUrl = `${APP_SCHEME}?${outgoingParams.toString()}`;

  console.log("Redirect URL:", redirectUrl);

  return Response.redirect(redirectUrl);
}
