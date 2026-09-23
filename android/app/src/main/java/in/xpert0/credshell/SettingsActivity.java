package in.xpert0.credshell;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SettingsActivity extends Activity {

    private TextView statusTextView;
    private TextView detailsTextView;
    private EditText endpointEditText;
    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(48, 64, 48, 64);

        TextView title = new TextView(this);
        title.setText("🔐 CredShell Passkey Bridge");
        title.setTextSize(22);
        title.setPadding(0, 0, 0, 24);
        layout.addView(title);

        TextView socketLabel = new TextView(this);
        socketLabel.setText("Hosted Socket Endpoint:");
        socketLabel.setTextSize(14);
        layout.addView(socketLabel);

        endpointEditText = new EditText(this);
        endpointEditText.setText(CredShellClient.getBaseUrl(this));
        endpointEditText.setSingleLine(true);
        layout.addView(endpointEditText);

        statusTextView = new TextView(this);
        statusTextView.setText("Checking connection to socket...");
        statusTextView.setTextSize(16);
        statusTextView.setPadding(0, 16, 0, 8);
        layout.addView(statusTextView);

        detailsTextView = new TextView(this);
        detailsTextView.setText("Ready for WhatsApp, Google, and native Android passkey requests.");
        detailsTextView.setTextSize(13);
        detailsTextView.setPadding(0, 0, 0, 32);
        layout.addView(detailsTextView);

        Button saveTestButton = new Button(this);
        saveTestButton.setText("Save & Test Connection");
        saveTestButton.setOnClickListener(v -> {
            String url = endpointEditText.getText().toString().trim();
            if (!url.isEmpty()) {
                CredShellClient.setBaseUrl(this, url);
            }
            checkConnection();
        });
        layout.addView(saveTestButton);

        Button openSettingsButton = new Button(this);
        openSettingsButton.setText("Open Android Credential Settings");
        openSettingsButton.setOnClickListener(v -> {
            boolean opened = false;
            String[] actions = new String[] {
                    "android.settings.CREDENTIAL_PROVIDER_SETTINGS",
                    "android.settings.REQUEST_SET_AUTOFILL_SERVICE",
                    Settings.ACTION_SETTINGS
            };
            for (String action : actions) {
                try {
                    Intent intent = new Intent(action);
                    startActivity(intent);
                    opened = true;
                    break;
                } catch (Exception ignored) {}
            }
            if (!opened) {
                Toast.makeText(this, "Please open Android Settings -> Passwords, passkeys & accounts", Toast.LENGTH_LONG).show();
            }
        });
        layout.addView(openSettingsButton);

        setContentView(layout);
        checkConnection();
    }

    private void checkConnection() {
        String currentUrl = CredShellClient.getBaseUrl(this);
        statusTextView.setText("Pinging " + currentUrl + "/status...");
        statusTextView.setTextColor(0xFF888888);

        executor.execute(() -> {
            CredShellClient.StatusCheckResult result = CredShellClient.checkStatus(this);
            mainHandler.post(() -> {
                if (result.success) {
                    statusTextView.setText("● Connected to CredShell Socket!");
                    statusTextView.setTextColor(0xFF00AA00);
                    detailsTextView.setText("Socket active (" + currentUrl + ")\n" + result.detail);
                } else {
                    statusTextView.setText("○ Offline: " + result.message);
                    statusTextView.setTextColor(0xFFAA0000);
                    detailsTextView.setText(result.detail);
                }
            });
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        checkConnection();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }
}
