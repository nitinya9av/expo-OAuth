import { ThemedText } from "./ThemedText";
import { useAuth } from "@/context/auth";
import { Button, Image, StyleSheet, View } from "react-native";
import { useState, useEffect } from "react";
import { tokenCache } from "@/utils/cache";

export default function ProfileCard() {
  const { signOut, user } = useAuth();
  const [apiAccessToken, setApiAccessToken] = useState<string | null>(null);
  const [apiATexpiry, setApiATexpiry] = useState<number | null>(null);
  const [apiRefreshToken, setApiRefreshToken] = useState<string | null>(null);

  useEffect(() => {
    const fetchApiTokens = async () => {
      // Fetch API access token
      const storedApiAccessToken = await tokenCache?.getToken("apiAccessToken");
      setApiAccessToken(storedApiAccessToken);

      // Fetch API refresh token
      const storedApiRefreshToken = await tokenCache?.getToken("apiRefreshToken");
      setApiRefreshToken(storedApiRefreshToken);

      // Fetch API access token expiry time
      const storedApiATexpiry = await tokenCache?.getExpiryTime("apiExpiryTime");
      setApiATexpiry(storedApiATexpiry);
    };

    // Fetch tokens once when the component mounts
    fetchApiTokens();
  }, [user]);

  return (
    <View
      style={{
        width: "90%",
        maxWidth: 400,
        gap: 20,
        padding: 20,
        borderRadius: 12,
        borderWidth: StyleSheet.hairlineWidth,
        borderColor: "gray",
      }}
    >
      <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
        <Image
          source={{ uri: user?.picture }}
          style={{
            width: 50,
            height: 50,
            borderRadius: 25,
          }}
        />

        <View>
          <ThemedText type="defaultSemiBold" style={{ textAlign: "center" }}>
            {user?.name}
          </ThemedText>
          <ThemedText style={{ fontSize: 14, color: "gray" }}>
            {user?.email}
          </ThemedText>
        </View>
      </View>

      <View>
        <ThemedText type="defaultSemiBold" style={{ textAlign: "center" }}>
          API Access Token:
        </ThemedText>
        <ThemedText
          type="defaultSemiBold"
          style={{
            textAlign: "center",
            fontSize: 12,
            color: "gray",
            wordWrap: "break-word",
          }}
        >
          {apiAccessToken !== null ? apiAccessToken : "No API Access Token"}
        </ThemedText>
      </View>

      <View>
        <ThemedText type="defaultSemiBold" style={{ textAlign: "center" }}>
          API Access Token Expiry:
        </ThemedText>
        <ThemedText
          type="defaultSemiBold"
          style={{
            textAlign: "center",
            fontSize: 12,
            color: "gray",
            wordWrap: "break-word",
          }}
        >
          {apiATexpiry !== null ? apiATexpiry : "No Api Access Token Expiry"}
        </ThemedText>
      </View>

      <View>
        <ThemedText type="defaultSemiBold" style={{ textAlign: "center" }}>
          API Refresh Token:
        </ThemedText>
        <ThemedText
          type="defaultSemiBold"
          style={{
            textAlign: "center",
            fontSize: 12,
            color: "gray",
            wordWrap: "break-word",
          }}
        >
          {apiRefreshToken !== null ? apiRefreshToken : "No API Refresh Token"}
        </ThemedText>
      </View>

      <Button title="Sign Out" onPress={signOut} color={"red"} />
    </View>
  );
}