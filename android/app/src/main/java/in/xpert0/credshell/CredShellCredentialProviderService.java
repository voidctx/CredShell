package in.xpert0.credshell;

import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.os.OutcomeReceiver;
import android.util.Base64;
import android.util.Log;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.credentials.exceptions.ClearCredentialException;
import androidx.credentials.exceptions.ClearCredentialUnknownException;
import androidx.credentials.exceptions.CreateCredentialException;
import androidx.credentials.exceptions.CreateCredentialUnknownException;
import androidx.credentials.exceptions.GetCredentialException;
import androidx.credentials.exceptions.GetCredentialUnknownException;
import androidx.credentials.provider.BeginCreateCredentialRequest;
import androidx.credentials.provider.BeginCreateCredentialResponse;
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialOption;
import androidx.credentials.provider.BeginGetCredentialRequest;
import androidx.credentials.provider.BeginGetCredentialResponse;
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption;
import androidx.credentials.provider.CallingAppInfo;
import androidx.credentials.provider.CreateEntry;
import androidx.credentials.provider.CredentialProviderService;
import androidx.credentials.provider.ProviderClearCredentialStateRequest;
import androidx.credentials.provider.PublicKeyCredentialEntry;

import java.security.MessageDigest;

@RequiresApi(api = Build.VERSION_CODES.UPSIDE_DOWN_CAKE)
public class CredShellCredentialProviderService extends CredentialProviderService {
    private static final String TAG = "CredShellProvider";
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    public void onBeginCreateCredentialRequest(
            @NonNull BeginCreateCredentialRequest request,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException> callback) {

        Log.i(TAG, "onBeginCreateCredentialRequest: type=" + request.getType());

        try {
            String requestJson = "";
            if (request instanceof BeginCreatePublicKeyCredentialRequest) {
                requestJson = ((BeginCreatePublicKeyCredentialRequest) request).getRequestJson();
            } else if (request.getCandidateQueryData() != null) {
                requestJson = request.getCandidateQueryData().getString("androidx.credentials.BUNDLE_KEY_REQUEST_JSON", "");
                if (requestJson.isEmpty()) {
                    requestJson = request.getCandidateQueryData().getString("android.credentials.BUNDLE_KEY_SUBTYPE", "");
                }
            }

            CallingAppInfo callingAppInfo = request.getCallingAppInfo();
            String origin = null;
            String packageName = null;
            if (callingAppInfo != null) {
                packageName = callingAppInfo.getPackageName();
                origin = getAppOrigin(callingAppInfo, getPackageManager());
            }

            final String appLabel = (packageName != null) ? packageName : "app";
            mainHandler.post(() -> {
                Toast.makeText(getApplicationContext(), "CredShell: Passkey request from " + appLabel, Toast.LENGTH_SHORT).show();
            });

            Intent intent = new Intent(this, AuthActivity.class);
            intent.putExtra(AuthActivity.EXTRA_TYPE, AuthActivity.TYPE_CREATE);
            intent.putExtra(AuthActivity.EXTRA_REQUEST_JSON, requestJson);
            if (origin != null) {
                intent.putExtra(AuthActivity.EXTRA_ORIGIN, origin);
            }
            if (packageName != null) {
                intent.putExtra(AuthActivity.EXTRA_PACKAGE_NAME, packageName);
            }

            PendingIntent pendingIntent = PendingIntent.getActivity(
                    this,
                    1001,
                    intent,
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
            );

            String userLabel = "Passkey Account";
            try {
                if (requestJson != null && !requestJson.isEmpty()) {
                    org.json.JSONObject obj = new org.json.JSONObject(requestJson);
                    org.json.JSONObject user = obj.optJSONObject("user");
                    if (user != null) {
                        String name = user.optString("name", user.optString("displayName", ""));
                        if (!name.isEmpty()) userLabel = name;
                    }
                }
            } catch (Exception ignored) {}

            CreateEntry createEntry = new CreateEntry.Builder(
                    userLabel,
                    pendingIntent
            )
            .setDescription("Save passkey in CredShell")
            .build();

            BeginCreateCredentialResponse response = new BeginCreateCredentialResponse.Builder()
                    .addCreateEntry(createEntry)
                    .build();

            callback.onResult(response);
        } catch (Exception e) {
            Log.e(TAG, "onBeginCreateCredentialRequest error: " + e.getMessage(), e);
            callback.onError(new CreateCredentialUnknownException(e.getMessage()));
        }
    }

    @Override
    public void onBeginGetCredentialRequest(
            @NonNull BeginGetCredentialRequest request,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException> callback) {

        Log.i(TAG, "onBeginGetCredentialRequest");

        try {
            BeginGetCredentialResponse.Builder responseBuilder = new BeginGetCredentialResponse.Builder();

            CallingAppInfo callingAppInfo = request.getCallingAppInfo();
            String origin = null;
            String packageName = null;
            if (callingAppInfo != null) {
                packageName = callingAppInfo.getPackageName();
                origin = getAppOrigin(callingAppInfo, getPackageManager());
            }

            final String appLabel = (packageName != null) ? packageName : "app";
            mainHandler.post(() -> {
                Toast.makeText(getApplicationContext(), "CredShell: Sign-in request for " + appLabel, Toast.LENGTH_SHORT).show();
            });

            for (BeginGetCredentialOption option : request.getBeginGetCredentialOptions()) {
                if (option instanceof BeginGetPublicKeyCredentialOption) {
                    BeginGetPublicKeyCredentialOption pkOption = (BeginGetPublicKeyCredentialOption) option;
                    String requestJson = pkOption.getRequestJson();

                    Intent intent = new Intent(this, AuthActivity.class);
                    intent.putExtra(AuthActivity.EXTRA_TYPE, AuthActivity.TYPE_GET);
                    intent.putExtra(AuthActivity.EXTRA_REQUEST_JSON, requestJson);
                    if (origin != null) {
                        intent.putExtra(AuthActivity.EXTRA_ORIGIN, origin);
                    }
                    if (packageName != null) {
                        intent.putExtra(AuthActivity.EXTRA_PACKAGE_NAME, packageName);
                    }

                    PendingIntent pendingIntent = PendingIntent.getActivity(
                            this,
                            1002,
                            intent,
                            PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT
                    );

                    PublicKeyCredentialEntry credEntry = new PublicKeyCredentialEntry.Builder(
                            this,
                            "CredShell Passkey",
                            pendingIntent,
                            pkOption
                    )
                    .setDisplayName("Tap to authenticate")
                    .build();

                    responseBuilder.addCredentialEntry(credEntry);
                }
            }

            callback.onResult(responseBuilder.build());
        } catch (Exception e) {
            Log.e(TAG, "onBeginGetCredentialRequest error: " + e.getMessage(), e);
            callback.onError(new GetCredentialUnknownException(e.getMessage()));
        }
    }

    @Override
    public void onClearCredentialStateRequest(
            @NonNull ProviderClearCredentialStateRequest request,
            @NonNull CancellationSignal cancellationSignal,
            @NonNull OutcomeReceiver<Void, ClearCredentialException> callback) {
        callback.onResult(null);
    }

    public static String getAppOrigin(CallingAppInfo callingAppInfo, PackageManager pm) {
        if (callingAppInfo == null) {
            return null;
        }
        String explicitOrigin = callingAppInfo.getOrigin();
        if (explicitOrigin != null && !explicitOrigin.trim().isEmpty()) {
            return explicitOrigin.trim();
        }
        return computeOriginFromPackage(callingAppInfo.getPackageName(), callingAppInfo.getSigningInfo(), pm);
    }

    public static String computeOriginFromPackage(
            String packageName,
            SigningInfo signingInfo,
            PackageManager pm) {

        if (packageName == null || packageName.trim().isEmpty()) {
            return null;
        }

        if ("com.whatsapp".equals(packageName) || "com.whatsapp.w4b".equals(packageName)) {
            return "android:apk-key-hash:OYfQQ9EK769ahxCzZxQY_lfg4ZtlPJ34JVj-tf_OXUQ";
        }

        Signature[] signatures = null;
        if (signingInfo != null) {
            if (signingInfo.hasMultipleSigners()) {
                signatures = signingInfo.getApkContentsSigners();
            } else {
                signatures = signingInfo.getSigningCertificateHistory();
            }
        }

        if ((signatures == null || signatures.length == 0) && pm != null) {
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    android.content.pm.PackageInfo pkgInfo = pm.getPackageInfo(
                            packageName,
                            PackageManager.GET_SIGNING_CERTIFICATES
                    );
                    if (pkgInfo != null && pkgInfo.signingInfo != null) {
                        if (pkgInfo.signingInfo.hasMultipleSigners()) {
                            signatures = pkgInfo.signingInfo.getApkContentsSigners();
                        } else {
                            signatures = pkgInfo.signingInfo.getSigningCertificateHistory();
                        }
                    }
                } else {
                    @SuppressWarnings("deprecation")
                    android.content.pm.PackageInfo pkgInfo = pm.getPackageInfo(
                            packageName,
                            PackageManager.GET_SIGNATURES
                    );
                    if (pkgInfo != null) {
                        signatures = pkgInfo.signatures;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "Failed to retrieve package signatures for " + packageName + ": " + e);
            }
        }

        if (signatures == null || signatures.length == 0) {
            return null;
        }

        Signature activeCert = signatures[signatures.length - 1];
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(activeCert.toByteArray());
            String b64 = Base64.encodeToString(
                    digest,
                    Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING
            );
            String derivedOrigin = "android:apk-key-hash:" + b64;
            Log.i(TAG, "Derived native app origin for " + packageName + ": " + derivedOrigin);
            return derivedOrigin;
        } catch (Exception e) {
            Log.e(TAG, "Failed to compute cert SHA-256: " + e);
            return null;
        }
    }
}
