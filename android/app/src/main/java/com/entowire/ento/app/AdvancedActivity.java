package com.entowire.ento.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.entowire.ento.mobile.Mobile;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The details the main screen leaves out, for whoever helps (or is curious): the device's address
 * and network, who is signed in, its groups and role, peers, routes, DNS, the exit, its posture,
 * the last error and the versions; and Send logs.
 */
public class AdvancedActivity extends Activity {
    private final Handler handler = new Handler(Looper.getMainLooper());
    private LinearLayout rows;
    private TextView message;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);
        TextView title = Ui.text(this, "Advanced", 24, R.color.fg);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);
        rows = new LinearLayout(this);
        rows.setOrientation(LinearLayout.VERTICAL);
        rows.setPadding(0, Ui.dp(this, 12), 0, 0);
        root.addView(rows);

        // What the app logged, its crash reports and why Android ended it, for whoever helps.
        Button sendLogs = Ui.button(this, "Send logs", v -> sendLogs());
        Ui.setPrimary(sendLogs, false);
        ((LinearLayout.LayoutParams) sendLogs.getLayoutParams()).topMargin = Ui.dp(this, 28);
        root.addView(sendLogs);
        TextView about = Ui.text(this, "Shares the app's logs and crash reports as one file, through the apps you pick. Nothing leaves the phone otherwise.", 14, R.color.muted);
        about.setPadding(0, Ui.dp(this, 8), 0, 0);
        root.addView(about);
        message = Ui.text(this, "", 15, R.color.muted);
        message.setTextIsSelectable(true);
        message.setPadding(0, Ui.dp(this, 16), 0, 0);
        root.addView(message);

        setContentView(Ui.page(this, root));
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh.run();
    }

    @Override
    protected void onPause() {
        super.onPause();
        handler.removeCallbacks(refresh);
    }

    private final Runnable refresh = new Runnable() {
        @Override
        public void run() {
            show();
            handler.postDelayed(this, 2000);
        }
    };

    private void show() {
        rows.removeAllViews();
        try {
            JSONObject s = new JSONObject(Mobile.status(Agent.stateDir(this)));
            if (s.getBoolean("enrolled")) {
                row("Address", s.optString("address"));
                String net = Mobile.network(Agent.stateDir(this));
                if (!net.isEmpty()) row("Network", new JSONObject(net).optString("network"));
            } else {
                row("Address", "not joined");
            }
            row("Agent", s.getBoolean("running") ? "running" : "stopped");
            if (!s.optString("user").isEmpty()) row("Signed in as", s.getString("user"));
            else if (!s.optString("bound_user").isEmpty()) row("Belongs to", s.getString("bound_user") + " (signed out)");
            if (s.has("approved")) row("Approved", s.getBoolean("approved") ? "yes" : "no");
            row("Groups", join(s.optJSONArray("groups")));
            if (s.optBoolean("administers")) row("Role", "administers the network");
            JSONArray peers = s.optJSONArray("peers");
            if (peers != null) {
                int reachable = 0;
                StringBuilder list = new StringBuilder();
                for (int i = 0; i < peers.length(); i++) {
                    JSONObject p = peers.getJSONObject(i);
                    int ago = p.getInt("handshake_seconds_ago");
                    if (ago >= 0 && ago < 180) reachable++;
                    if (list.length() > 0) list.append('\n');
                    list.append(p.optString("endpoint", "?")).append(ago < 0 ? ", no handshake" : ", handshake " + ago + " s ago");
                }
                row("Peers", reachable + " of " + peers.length() + " connected" + (list.length() > 0 ? "\n" + list : ""));
            }
            row("Routes", join(s.optJSONArray("routes")));
            row("DNS server", s.optString("dns"));
            JSONArray exits = s.optJSONArray("exits");
            if (exits != null && exits.length() > 0) {
                StringBuilder e = new StringBuilder();
                for (int i = 0; i < exits.length(); i++) {
                    JSONObject x = exits.getJSONObject(i);
                    if (e.length() > 0) e.append('\n');
                    e.append(x.optString("route")).append(" via ").append(x.optString("via")).append(x.optBoolean("in_use") ? " (in use)" : "");
                }
                row("Exits", e.toString());
            }
            row("Posture", s.optString("posture"));
            JSONArray failing = s.optJSONArray("posture_failing");
            if (failing != null && failing.length() > 0) {
                StringBuilder f = new StringBuilder();
                for (int i = 0; i < failing.length(); i++) {
                    JSONObject x = failing.getJSONObject(i);
                    if (f.length() > 0) f.append('\n');
                    f.append(x.optString("check")).append(": ").append(x.optString("reason"));
                }
                row("Failing checks", f.toString());
            }
            if (s.has("attested")) row("Attestation", s.get("attested").toString());
            row("Last error", s.optString("error"));
            row("Agent version", s.optString("version"));
        } catch (Exception e) {
            row("Error", String.valueOf(e.getMessage()));
        }
        String version = "?";
        try {
            version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception ignored) {
        }
        row("App version", version);
    }

    /** A label over its value; an empty value is left out. */
    private void row(String label, String value) {
        if (value == null || value.isEmpty()) return;
        TextView l = Ui.text(this, label, 13, R.color.muted);
        l.setPadding(0, Ui.dp(this, 14), 0, 0);
        rows.addView(l);
        TextView v = Ui.text(this, value, 15, R.color.fg);
        v.setTextIsSelectable(true);
        rows.addView(v);
    }

    private static String join(JSONArray a) throws org.json.JSONException {
        if (a == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < a.length(); i++) sb.append(i > 0 ? ", " : "").append(a.getString(i));
        return sb.toString();
    }

    /**
     * Shares the logs (Mobile.logs: crash reports, Android's exit reasons, the log file) with the
     * device's description and the agent's status, through Android's share sheet, as a file the
     * person sends where they choose. Nothing leaves the phone otherwise.
     */
    private void sendLogs() {
        message.setText("Collecting the logs...");
        new Thread(() -> {
            try {
                StringBuilder sb = new StringBuilder();
                sb.append("ento logs, ").append(java.time.Instant.now()).append('\n')
                        .append(Build.MANUFACTURER).append(' ').append(Build.MODEL).append(", Android ").append(Build.VERSION.RELEASE)
                        .append(" (SDK ").append(Build.VERSION.SDK_INT).append(", patch ").append(Build.VERSION.SECURITY_PATCH).append(")\n")
                        .append("status: ").append(Mobile.status(Agent.stateDir(this))).append("\n\n")
                        .append(Mobile.logs());
                try (java.io.FileOutputStream out = new java.io.FileOutputStream(LogsProvider.file(this))) {
                    out.write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
                Uri uri = LogsProvider.uri();
                Intent send = new Intent(Intent.ACTION_SEND).setType("text/plain")
                        .putExtra(Intent.EXTRA_STREAM, uri)
                        .putExtra(Intent.EXTRA_SUBJECT, "ento logs from " + Agent.hostname(this))
                        .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
                send.setClipData(android.content.ClipData.newRawUri("", uri));
                runOnUiThread(() -> {
                    message.setText("");
                    startActivity(Intent.createChooser(send, "Send the logs to"));
                });
            } catch (Exception e) {
                runOnUiThread(() -> message.setText("Logs: " + e.getMessage()));
            }
        }).start();
    }
}
