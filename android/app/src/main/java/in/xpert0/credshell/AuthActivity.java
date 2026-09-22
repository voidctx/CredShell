package in.xpert0.credshell;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.widget.Toast;

import androidx.credentials.CreatePublicKeyCredentialRequest;
import androidx.credentials.CreatePublicKeyCredentialResponse;
import androidx.credentials.CredentialOption;
import androidx.credentials.GetCredentialResponse;
import androidx.credentials.GetPublicKeyCredentialOption;
import androidx.credentials.PublicKeyCredential;
import androidx.credentials.provider.PendingIntentHandler;
import androidx.credentials.provider.ProviderCreateCredentialRequest;
import androidx.credentials.provider.ProviderGetCredentialRequest;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class AuthActivity extends Activity {
    private static final String TAG = "CredShellProvider";

    public static final String EXTRA_TYPE = "credshell_type";
    public static final String EXTRA_REQUEST_JSON = "credshell_request_json";
    public static final String EXTRA_ORIGIN = "credshell_origin";
    public static final String EXTRA_PACKAGE_NAME = "credshell_package_name";
    public static final String TYPE_CREATE = "create";
    public static final String TYPE_GET = "get";

    public static final String EXTRA_CREATE_CREDENTIAL_RESPONSE = "android.service.credentials.extra.CREATE_CREDENTIAL_RESPONSE";
    public static final String EXTRA_GET_CREDENTIAL_RESPONSE = "android.service.credentials.extra.GET_CREDENTIAL_RESPONSE";

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        Intent intent = getIntent();
        if (intent == null) {
            Log.e(TAG, "AuthActivity received null intent");
            finish();
            return;
        }

        String type = intent.getStringExtra(EXTRA_TYPE);
        String requestJson = extractRequestJson(intent);
        String origin = extractOrigin(intent);
        String packageName = extractPackageName(intent);

        if (type == null) {
            type = (intent.hasExtra("android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST")) ? TYPE_CREATE : TYPE_GET;
        }

        Log.i(TAG, "Starting auth flow: type=" + type + ", pkg=" + packageName + ", origin=" + origin + ", jsonLen=" + requestJson.length());
        final String finalType = type;
        final String finalRequestJson = requestJson;
        final String finalOrigin = origin;
        final String finalPackageName = packageName;

        Toast.makeText(this, "CredShell: Authenticating with passkey server...", Toast.LENGTH_SHORT).show();

        executor.execute(() -> {
            try {
                if (TYPE_CREATE.equals(finalType)) {
                    Log.i(TAG, "Sending create request to CredShell socket...");
                    String responseJson = CredShellClient.createPasskey(this, finalRequestJson, finalOrigin, finalPackageName);
                    Log.i(TAG, "CredShell create succeeded, response: " + responseJson);

                    mainHandler.post(() -> {
                        Intent resultIntent = new Intent();

                        CreatePublicKeyCredentialResponse jetpackResponse = new CreatePublicKeyCredentialResponse(responseJson);
                        PendingIntentHandler.setCreateCredentialResponse(resultIntent, jetpackResponse);

                        Bundle data = new Bundle();
                        data.putString("androidx.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson);
                        data.putString("androidx.credentials.BUNDLE_KEY_RESPONSE_JSON", responseJson);
                        data.putString("android.credentials.BUNDLE_KEY_REGISTRATION_RESPONSE_JSON", responseJson);
                        android.credentials.CreateCredentialResponse frameworkResp = new android.credentials.CreateCredentialResponse(data);
                        resultIntent.putExtra(EXTRA_CREATE_CREDENTIAL_RESPONSE, frameworkResp);

                        setResult(Activity.RESULT_OK, resultIntent);
                        finish();
                    });
                } else {
                    Log.i(TAG, "Sending get/assertion request to CredShell socket...");
                    String responseJson = CredShellClient.getPasskey(this, finalRequestJson, finalOrigin, finalPackageName);
                    Log.i(TAG, "CredShell get succeeded, response: " + responseJson);

                    mainHandler.post(() -> {
                        Intent resultIntent = new Intent();

                        PublicKeyCredential cred = new PublicKeyCredential(responseJson);
                        GetCredentialResponse jetpackResponse = new GetCredentialResponse(cred);
                        PendingIntentHandler.setGetCredentialResponse(resultIntent, jetpackResponse);

                        Bundle data = new Bundle();
                        data.putString("androidx.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson);
                        data.putString("androidx.credentials.BUNDLE_KEY_RESPONSE_JSON", responseJson);
                        data.putString("android.credentials.BUNDLE_KEY_AUTHENTICATION_RESPONSE_JSON", responseJson);
                        android.credentials.Credential frameworkCred = new android.credentials.Credential(
                                "androidx.credentials.TYPE_PUBLIC_KEY_CREDENTIAL",
                                data
                        );
                        android.credentials.GetCredentialResponse frameworkResp = new android.credentials.GetCredentialResponse(frameworkCred);
                        resultIntent.putExtra(EXTRA_GET_CREDENTIAL_RESPONSE, frameworkResp);

                        setResult(Activity.RESULT_OK, resultIntent);
                        finish();
                    });
                }
            } catch (Exception e) {
                final String errorMsg = e.getMessage() != null ? e.getMessage() : "Authentication failed";
                Log.e(TAG, "AuthActivity execution error: " + errorMsg, e);
                mainHandler.post(() -> {
                    Toast.makeText(
                            AuthActivity.this,
                            "CredShell: " + errorMsg + "\nCheck socket at " + CredShellClient.getBaseUrl(AuthActivity.this),
                            Toast.LENGTH_LONG
                    ).show();
                    setResult(Activity.RESULT_CANCELED);
                    finish();
                });
            }
        });
    }

    private String extractRequestJson(Intent intent) {
        String extra = intent.getStringExtra(EXTRA_REQUEST_JSON);
        if (extra != null && !extra.trim().isEmpty() && !extra.trim().equals("{}")) {
            return extra;
        }

        try {
            ProviderCreateCredentialRequest providerCreate = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent);
            if (providerCreate != null) {
                androidx.credentials.CreateCredentialRequest calling = providerCreate.getCallingRequest();
                if (calling instanceof CreatePublicKeyCredentialRequest) {
                    String json = ((CreatePublicKeyCredentialRequest) calling).getRequestJson();
                    if (json != null && !json.trim().isEmpty()) return json;
                }
                if (calling != null && calling.getCredentialData() != null) {
                    String json = calling.getCredentialData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                    if (json != null && !json.trim().isEmpty()) return json;
                }
                if (calling != null && calling.getCandidateQueryData() != null) {
                    String json = calling.getCandidateQueryData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                    if (json != null && !json.trim().isEmpty()) return json;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "retrieveProviderCreateCredentialRequest inspection: " + t);
        }

        try {
            ProviderGetCredentialRequest providerGet = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent);
            if (providerGet != null) {
                for (CredentialOption opt : providerGet.getCredentialOptions()) {
                    if (opt instanceof GetPublicKeyCredentialOption) {
                        String json = ((GetPublicKeyCredentialOption) opt).getRequestJson();
                        if (json != null && !json.trim().isEmpty()) return json;
                    }
                    if (opt.getRequestData() != null) {
                        String json = opt.getRequestData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                        if (json != null && !json.trim().isEmpty()) return json;
                    }
                    if (opt.getCandidateQueryData() != null) {
                        String json = opt.getCandidateQueryData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                        if (json != null && !json.trim().isEmpty()) return json;
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "retrieveProviderGetCredentialRequest inspection: " + t);
        }

        try {
            android.credentials.CreateCredentialRequest frameworkCreate = intent.getParcelableExtra(
                    "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST"
            );
            if (frameworkCreate != null) {
                if (frameworkCreate.getCredentialData() != null) {
                    String json = frameworkCreate.getCredentialData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                    if (json != null && !json.trim().isEmpty()) return json;
                }
                if (frameworkCreate.getCandidateQueryData() != null) {
                    String json = frameworkCreate.getCandidateQueryData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                    if (json != null && !json.trim().isEmpty()) return json;
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "framework CreateCredentialRequest inspection: " + t);
        }

        try {
            android.credentials.GetCredentialRequest frameworkGet = intent.getParcelableExtra(
                    "android.service.credentials.extra.GET_CREDENTIAL_REQUEST"
            );
            if (frameworkGet != null) {
                for (android.credentials.CredentialOption opt : frameworkGet.getCredentialOptions()) {
                    Bundle data = opt.getCredentialRetrievalData() != null ? opt.getCredentialRetrievalData() : opt.getCandidateQueryData();
                    if (data != null && data.containsKey("androidx.credentials.BUNDLE_KEY_REQUEST_JSON")) {
                        String json = data.getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON");
                        if (json != null && !json.trim().isEmpty()) return json;
                    }
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "framework GetCredentialRequest inspection: " + t);
        }

        return "{}";
    }

    private String extractOrigin(Intent intent) {
        String directOrigin = intent.getStringExtra(EXTRA_ORIGIN);
        if (directOrigin != null && !directOrigin.trim().isEmpty()) {
            return directOrigin;
        }

        try {
            ProviderCreateCredentialRequest providerCreate = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent);
            if (providerCreate != null && providerCreate.getCallingAppInfo() != null) {
                String origin = CredShellCredentialProviderService.getAppOrigin(providerCreate.getCallingAppInfo(), getPackageManager());
                if (origin != null && !origin.trim().isEmpty()) return origin;
            }
        } catch (Throwable ignored) {}

        try {
            ProviderGetCredentialRequest providerGet = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent);
            if (providerGet != null && providerGet.getCallingAppInfo() != null) {
                String origin = CredShellCredentialProviderService.getAppOrigin(providerGet.getCallingAppInfo(), getPackageManager());
                if (origin != null && !origin.trim().isEmpty()) return origin;
            }
        } catch (Throwable ignored) {}

        try {
            android.credentials.CreateCredentialRequest frameworkCreate = intent.getParcelableExtra(
                    "android.service.credentials.extra.CREATE_CREDENTIAL_REQUEST"
            );
            if (frameworkCreate != null && frameworkCreate.getOrigin() != null) {
                return frameworkCreate.getOrigin();
            }
        } catch (Throwable ignored) {}

        try {
            android.credentials.GetCredentialRequest frameworkGet = intent.getParcelableExtra(
                    "android.service.credentials.extra.GET_CREDENTIAL_REQUEST"
            );
            if (frameworkGet != null && frameworkGet.getOrigin() != null) {
                return frameworkGet.getOrigin();
            }
        } catch (Throwable ignored) {}

        return null;
    }

    private String extractPackageName(Intent intent) {
        String directPkg = intent.getStringExtra(EXTRA_PACKAGE_NAME);
        if (directPkg != null && !directPkg.trim().isEmpty()) {
            return directPkg;
        }

        try {
            ProviderCreateCredentialRequest providerCreate = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent);
            if (providerCreate != null && providerCreate.getCallingAppInfo() != null) {
                String pkg = providerCreate.getCallingAppInfo().getPackageName();
                if (pkg != null && !pkg.trim().isEmpty()) return pkg;
            }
        } catch (Throwable ignored) {}

        try {
            ProviderGetCredentialRequest providerGet = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent);
            if (providerGet != null && providerGet.getCallingAppInfo() != null) {
                String pkg = providerGet.getCallingAppInfo().getPackageName();
                if (pkg != null && !pkg.trim().isEmpty()) return pkg;
            }
        } catch (Throwable ignored) {}

        return null;
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
