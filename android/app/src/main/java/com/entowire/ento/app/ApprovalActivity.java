package com.entowire.ento.app;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.entowire.ento.mobile.Mobile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.time.Instant;

/**
 * A sign-in that waits for this phone's approval: which device, which account, what for, and three
 * numbers. The person picks the one the device shows (a request they did not start has no number
 * in front of them), confirms with a fingerprint or the screen lock, and the app sends the answer
 * signed with the phone's key. A wrong number denies the sign-in.
 */
public class ApprovalActivity extends Activity {
    static final String EXTRA = "approval";
    private static final int CONFIRM = 1;
    private static final int VOID = Color.rgb(0x0b, 0x0c, 0x0e);
    private static final int INK = Color.rgb(0xe9, 0xea, 0xec);
    private static final int DIM = Color.rgb(0x8a, 0x8e, 0x96);

    private final Handler handler = new Handler(Looper.getMainLooper());
    private String id, device, user, service;
    private long expires;
    private TextView message;
    private LinearLayout numbers;
    private Button deny;
    private int picked;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(VOID);
        root.setPadding(dp(24), dp(48), dp(24), dp(24));
        try {
            JSONObject a = new JSONObject(getIntent().getStringExtra(EXTRA));
            id = a.getString("id");
            device = a.getString("device");
            user = a.getString("user");
            service = a.getString("service");
            expires = Instant.parse(a.getString("expires_at")).toEpochMilli();
            TextView title = text("Sign in to " + device + "?", 24, INK);
            title.setTypeface(Typeface.DEFAULT_BOLD);
            root.addView(title);
            root.addView(text("As " + user + ", for " + service + ".\n\nPick the number " + device
                    + " shows. If it shows none, or you did not just sign in there, deny.", 16, DIM));
            numbers = new LinearLayout(this);
            numbers.setOrientation(LinearLayout.HORIZONTAL);
            numbers.setGravity(Gravity.CENTER);
            numbers.setPadding(0, dp(28), 0, dp(28));
            JSONArray choices = a.getJSONArray("choices");
            for (int i = 0; i < choices.length(); i++) {
                int n = choices.getInt(i);
                Button b = new Button(this);
                b.setText(String.valueOf(n));
                b.setTextSize(32);
                b.setOnClickListener(v -> pick(n));
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(96), 1);
                lp.setMargins(dp(6), 0, dp(6), 0);
                numbers.addView(b, lp);
            }
            root.addView(numbers);
            deny = new Button(this);
            deny.setText("Deny");
            deny.setOnClickListener(v -> answer(0, false));
            root.addView(deny);
        } catch (Exception e) {
            root.addView(text("This request could not be read.", 16, INK));
        }
        message = text("", 16, INK);
        message.setPadding(0, dp(20), 0, 0);
        root.addView(message);
        setContentView(root);
        handler.post(countdown);
    }

    private final Runnable countdown = new Runnable() {
        @Override
        public void run() {
            long left = (expires - System.currentTimeMillis()) / 1000;
            if (left <= 0) {
                done("This request has expired.");
                return;
            }
            if (picked == 0) message.setText(left + " s left");
            handler.postDelayed(this, 1000);
        }
    };

    private void pick(int n) {
        KeyguardManager km = getSystemService(KeyguardManager.class);
        if (km == null || !km.isDeviceSecure()) {
            message.setText("Set a screen lock on this phone to approve sign-ins.");
            return;
        }
        picked = n;
        String title = "Approve the sign-in to " + device;
        String what = user + ", " + service + ", number " + n;
        if (Build.VERSION.SDK_INT >= 29) {
            BiometricPrompt.Builder b = new BiometricPrompt.Builder(this).setTitle(title).setSubtitle(what);
            if (Build.VERSION.SDK_INT >= 30) {
                b.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                        | BiometricManager.Authenticators.DEVICE_CREDENTIAL);
            } else {
                b.setDeviceCredentialAllowed(true);
            }
            b.build().authenticate(new CancellationSignal(), getMainExecutor(), new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult r) {
                    answer(picked, true);
                }

                @Override
                public void onAuthenticationError(int code, CharSequence msg) {
                    picked = 0;
                    message.setText(msg);
                }
            });
        } else {
            Intent i = km.createConfirmDeviceCredentialIntent(title, what);
            if (i == null) {
                answer(picked, true);
            } else {
                startActivityForResult(i, CONFIRM);
            }
        }
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request != CONFIRM) return;
        if (result == RESULT_OK) {
            answer(picked, true);
        } else {
            picked = 0;
            message.setText("Not confirmed.");
        }
    }

    private void answer(int n, boolean approve) {
        setButtons(false);
        message.setText(approve ? "Approving…" : "Denying…");
        String dir = Agent.stateDir(this);
        new Thread(() -> {
            String outcome;
            try {
                String state = Mobile.answerApproval(dir, id, n, approve);
                outcome = "approved".equals(state) ? "Approved."
                        : approve ? "Denied: that is not the number " + device + " shows." : "Denied.";
            } catch (Exception e) {
                outcome = "Could not answer: " + e.getMessage();
            }
            String o = outcome;
            runOnUiThread(() -> done(o));
        }).start();
    }

    private void done(String text) {
        handler.removeCallbacks(countdown);
        setButtons(false);
        message.setText(text);
        handler.postDelayed(this::finish, 2500);
    }

    private void setButtons(boolean on) {
        if (numbers != null) {
            for (int i = 0; i < numbers.getChildCount(); i++) numbers.getChildAt(i).setEnabled(on);
        }
        if (deny != null) deny.setEnabled(on);
    }

    private TextView text(String s, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        return t;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
