package in.xpert0.credshell;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

public class CredShellClient {
    public static final String DEFAULT_SOCKET_URL = "http://127.0.0.1:5209";
    private static final String PREF_NAME = "credshell_config";
    private static final String KEY_SOCKET_URL = "socket_url";
    private static final String KEY_TUNNEL_PASSWORD_HASH = "tunnel_password_hash";

    public static String getBaseUrl(Context context) {
        if (context == null) {
            return DEFAULT_SOCKET_URL;
        }
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        return prefs.getString(KEY_SOCKET_URL, DEFAULT_SOCKET_URL);
    }

    public static void setBaseUrl(Context context, String url) {
        if (context == null || url == null || url.trim().isEmpty()) {
            return;
        }
        String cleanUrl = url.trim();
        if (cleanUrl.endsWith("/")) {
            cleanUrl = cleanUrl.substring(0, cleanUrl.length() - 1);
        }
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_SOCKET_URL, cleanUrl).apply();
    }

    public static String getTunnelPasswordHash(Context context) {
        if (context == null) {
            return "";
        }
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        String hash = prefs.getString(KEY_TUNNEL_PASSWORD_HASH, "");
        return hash == null ? "" : hash.trim().toLowerCase(Locale.ROOT);
    }

    public static void setTunnelPassword(Context context, String password) {
        if (context == null) {
            return;
        }
        String hash = "";
        if (password != null && !password.trim().isEmpty()) {
            hash = sha256Hex(password.trim());
        }
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        prefs.edit().putString(KEY_TUNNEL_PASSWORD_HASH, hash).apply();
    }

    public static class StatusCheckResult {
        public final boolean success;
        public final int code;
        public final String message;
        public final String detail;

        public StatusCheckResult(boolean success, int code, String message, String detail) {
            this.success = success;
            this.code = code;
            this.message = message;
            this.detail = detail;
        }
    }

    public static StatusCheckResult checkStatus(Context context) {
        String base = getBaseUrl(context);
        String hash = getTunnelPasswordHash(context);
        if (!isLoopbackBase(base) && hash.isEmpty()) {
            return new StatusCheckResult(false, 0, "Tunnel password required",
                    "Set a tunnel password in CredShell app settings before connecting to a tunnel endpoint.");
        }
        try {
            URL url = new URL(base + "/status");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            if (!hash.isEmpty()) {
                conn.setRequestProperty("X-CredShell-Password-Hash", hash);
            }
            conn.setConnectTimeout(2500);
            conn.setReadTimeout(2500);
            int code = conn.getResponseCode();

            InputStream is = (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream();
            String respBody = "";
            if (is != null) {
                StringBuilder sb = new StringBuilder();
                try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        sb.append(line);
                    }
                }
                respBody = sb.toString();
            }

            if (code == 200) {
                return new StatusCheckResult(true, 200, "Connected",
                        "Socket active at " + base + "\nResponse: " + respBody);
            } else {
                return new StatusCheckResult(false, code, "HTTP " + code,
                        "Server returned HTTP " + code + ": " + respBody);
            }
        } catch (java.net.ConnectException ce) {
            return new StatusCheckResult(false, 0, "Connection Refused",
                    "Cannot reach " + base + "\n• Check if 'credshell passkey' is running in Termux\n• If running on phone, use http://127.0.0.1:5209\n• Detail: " + ce.getMessage());
        } catch (java.net.SocketTimeoutException te) {
            return new StatusCheckResult(false, 0, "Connection Timed Out",
                    "Timed out connecting to " + base + "\nCheck if Termux process is paused by battery saver.");
        } catch (Exception e) {
            return new StatusCheckResult(false, 0, e.getClass().getSimpleName(),
                    "Error: " + (e.getMessage() != null ? e.getMessage() : e.toString()));
        }
    }

    public static boolean isRunning(Context context) {
        return checkStatus(context).success;
    }

    public static String createPasskey(Context context, String requestJson, String origin, String packageName) throws Exception {
        String base = getBaseUrl(context);
        String payload = injectMetadata(requestJson, origin, packageName);
        return postJson(context, base + "/webauthn/create", payload);
    }

    public static String getPasskey(Context context, String requestJson, String origin, String packageName) throws Exception {
        String base = getBaseUrl(context);
        String payload = injectMetadata(requestJson, origin, packageName);
        return postJson(context, base + "/webauthn/get", payload);
    }

    public static String createPasskey(Context context, String requestJson, String origin) throws Exception {
        return createPasskey(context, requestJson, origin, null);
    }

    public static String getPasskey(Context context, String requestJson, String origin) throws Exception {
        return getPasskey(context, requestJson, origin, null);
    }

    private static String injectMetadata(String jsonStr, String origin, String packageName) {
        if (jsonStr == null || jsonStr.trim().isEmpty()) {
            jsonStr = "{}";
        }
        try {
            JSONObject json = new JSONObject(jsonStr);
            if (origin != null && !origin.isEmpty() && !json.has("origin")) {
                json.put("origin", origin);
            }
            if (packageName != null && !packageName.isEmpty()) {
                if (!json.has("package_name")) json.put("package_name", packageName);
                if (!json.has("packageName")) json.put("packageName", packageName);
            }
            json.put("auto_approve", true);

            JSONObject pk = json.optJSONObject("publicKey");
            if (pk != null) {
                if (origin != null && !origin.isEmpty() && !pk.has("origin")) {
                    pk.put("origin", origin);
                }
                if (packageName != null && !packageName.isEmpty()) {
                    if (!pk.has("package_name")) pk.put("package_name", packageName);
                    if (!pk.has("packageName")) pk.put("packageName", packageName);
                }
                pk.put("auto_approve", true);
            }

            return json.toString();
        } catch (Exception e) {
            return jsonStr;
        }
    }

    private static String postJson(Context context, String endpoint, String jsonPayload) throws Exception {
        URL url = new URL(endpoint);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        String hash = getTunnelPasswordHash(context);
        String base = endpoint;
        int idx = endpoint.indexOf('/', endpoint.indexOf("://") + 3);
        if (idx > 0) {
            base = endpoint.substring(0, idx);
        }
        if (!isLoopbackBase(base) && hash.isEmpty()) {
            throw new RuntimeException("Tunnel password is required for non-local endpoints");
        }
        if (!hash.isEmpty()) {
            conn.setRequestProperty("X-CredShell-Password-Hash", hash);
        }
        conn.setDoOutput(true);
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(90000);

        byte[] body = jsonPayload.getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
            os.flush();
        }

        int statusCode = conn.getResponseCode();
        InputStream is = (statusCode >= 200 && statusCode < 300) ? conn.getInputStream() : conn.getErrorStream();
        if (is == null) {
            throw new RuntimeException("HTTP " + statusCode + " with no response from CredShell socket");
        }

        StringBuilder response = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                response.append(line);
            }
        }

        if (statusCode >= 200 && statusCode < 300) {
            return response.toString();
        } else {
            throw new RuntimeException("CredShell error (" + statusCode + "): " + response.toString());
        }
    }

    private static boolean isLoopbackBase(String base) {
        try {
            URL url = new URL(base);
            String host = url.getHost();
            if (host == null) return false;
            host = host.trim().toLowerCase(Locale.ROOT);
            return host.equals("127.0.0.1") || host.equals("localhost") || host.equals("::1");
        } catch (Exception e) {
            return false;
        }
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(bytes.length * 2);
            for (byte b : bytes) {
                sb.append(String.format(Locale.ROOT, "%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
}
