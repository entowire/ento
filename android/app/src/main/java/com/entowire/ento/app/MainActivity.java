package com.entowire.ento.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import com.entowire.ento.mobile.Mobile;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * One screen: join with the domain and the words an administrator reads out (`ento admin token
 * --words`; phones take no tokens), or with the QR code of both their admin page shows (ScanActivity),
 * connect or disconnect, sign in, open the admin page (admin and operator devices), and what the
 * agent reports. Sign-in approvals open ApprovalActivity.
 */
public class MainActivity extends Activity {
    private static final int VPN_PERMISSION = 1;
    private static final int SCAN = 4;
    private static final int VOID = Color.rgb(0x0b, 0x0c, 0x0e);
    private static final int INK = Color.rgb(0xe9, 0xea, 0xec);
    private static final int DIM = Color.rgb(0x8a, 0x8e, 0x96);
    private static final int SIGNAL = Color.rgb(0x36, 0x56, 0xff);

    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView state, detail, message;
    private EditText adminCode, joinDomain, joinWords;
    private Button connect, signIn, adminPage, adminApprove, scan, lookUp, join, exit, sendLogs;
    private String exitChoice = ""; // what the exit button chooses: a route's name or "off"
    private TextView joinHeading, joinInfo;
    private String joinRecord; // the network record found for joinDomain, for the words

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(20);
        root.setBackgroundColor(VOID);

        TextView word = text("ento", 28, INK);
        word.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(word);
        state = text("", 22, INK);
        state.setPadding(0, dp(28), 0, 0);
        root.addView(state);
        detail = text("", 15, DIM);
        root.addView(detail);

        // Enrollment by words: the domain and five words an administrator reads out, or the QR code
        // of both that their admin page shows.
        scan = button("Scan the QR code", v -> startActivityForResult(new Intent(this, ScanActivity.class), SCAN));
        root.addView(scan);
        joinHeading = text("Or type the domain and the words your administrator reads out:", 15, DIM);
        joinHeading.setPadding(0, dp(20), 0, 0);
        root.addView(joinHeading);
        joinDomain = new EditText(this);
        joinDomain.setHint("Domain (e.g. example.com)");
        joinDomain.setTextColor(INK);
        joinDomain.setHintTextColor(DIM);
        joinDomain.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        root.addView(joinDomain, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        lookUp = button("Find the network", v -> lookUp(joinDomain.getText().toString(), null, null));
        root.addView(lookUp);
        joinInfo = text("", 15, INK);
        joinInfo.setVisibility(android.view.View.GONE);
        root.addView(joinInfo);
        joinWords = new EditText(this);
        joinWords.setHint("The five words");
        joinWords.setTextColor(INK);
        joinWords.setHintTextColor(DIM);
        joinWords.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        joinWords.setVisibility(android.view.View.GONE);
        root.addView(joinWords, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        join = button("Join", v -> joinWithWords(joinWords.getText().toString()));
        join.setVisibility(android.view.View.GONE);
        root.addView(join);
        connect = button("Connect", v -> toggle());
        root.addView(connect);
        signIn = button("Sign in", v -> signIn());
        root.addView(signIn);
        // An exit an administrator offers: all internet traffic through an office's gateway.
        exit = button("", v -> chooseExit());
        exit.setVisibility(android.view.View.GONE);
        root.addView(exit);
        adminPage = button("Open the admin page", v -> openAdminPage());
        root.addView(adminPage);
        adminCode = new EditText(this);
        adminCode.setHint("Code the admin page shows");
        adminCode.setTextColor(INK);
        adminCode.setHintTextColor(DIM);
        adminCode.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        adminCode.setVisibility(android.view.View.GONE);
        root.addView(adminCode, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        adminApprove = button("Approve", v -> approveAdminPage(adminCode.getText().toString()));
        adminApprove.setVisibility(android.view.View.GONE);
        root.addView(adminApprove);
        message = text("", 14, DIM);
        message.setTextIsSelectable(true);
        message.setPadding(0, dp(16), 0, 0);
        root.addView(message);
        // What the app logged, its crash reports and why Android ended it, for whoever helps.
        sendLogs = button("Send logs", v -> sendLogs());
        sendLogs.setBackgroundColor(Color.rgb(0x2a, 0x2d, 0x33));
        ((LinearLayout.LayoutParams) sendLogs.getLayoutParams()).topMargin = dp(32);
        root.addView(sendLogs);
        // Which version this is, at a glance (when someone asks, or before sending logs).
        String version = "?";
        try {
            version = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception ignored) {
        }
        TextView versionLine = text("ento " + version, 12, DIM);
        versionLine.setPadding(0, dp(12), 0, 0);
        root.addView(versionLine);

        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(VOID);
        scroll.addView(root);
        // The window is edge to edge: keep the content clear of the status and navigation bars.
        root.setPadding(pad, dp(24), pad, pad);
        if (Build.VERSION.SDK_INT >= 30) {
            scroll.setOnApplyWindowInsetsListener((v, insets) -> {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars() | WindowInsets.Type.ime());
                root.setPadding(pad + bars.left, dp(24) + bars.top, pad + bars.right, pad + bars.bottom);
                return WindowInsets.CONSUMED;
            });
        }
        setContentView(scroll);
    }

    @Override
    protected void onStart() {
        super.onStart();
        // Sign-in approvals arrive as notifications, which Android 13 and later must be allowed to show.
        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{android.Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        Agent.reportPosture(this); // a screen lock set meanwhile, for example
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
        try {
            JSONObject s = new JSONObject(Mobile.status(Agent.stateDir(this)));
            boolean enrolled = s.getBoolean("enrolled"), running = s.getBoolean("running");
            int joining = enrolled ? android.view.View.GONE : android.view.View.VISIBLE;
            scan.setVisibility(joining);
            joinHeading.setVisibility(joining);
            joinDomain.setVisibility(joining);
            lookUp.setVisibility(joining);
            if (enrolled || joinRecord == null) {
                joinInfo.setVisibility(enrolled ? android.view.View.GONE : joinInfo.getVisibility());
                joinWords.setVisibility(android.view.View.GONE);
                join.setVisibility(android.view.View.GONE);
            }
            connect.setVisibility(enrolled ? android.view.View.VISIBLE : android.view.View.GONE);
            // Sign in only helps a device that is not (or no longer) approved.
            boolean known = s.has("approved");
            boolean needsSignIn = running && (s.getBoolean("login_required") || (known && !s.getBoolean("approved")));
            signIn.setVisibility(needsSignIn ? android.view.View.VISIBLE : android.view.View.GONE);
            boolean administers = running && s.optBoolean("administers", false);
            adminPage.setVisibility(administers ? android.view.View.VISIBLE : android.view.View.GONE);
            if (!administers) {
                adminCode.setVisibility(android.view.View.GONE);
                adminApprove.setVisibility(android.view.View.GONE);
            }
            connect.setText(running ? "Disconnect" : "Connect");
            showExit(s, running);
            if (!enrolled) {
                state.setText("Not enrolled");
                detail.setText("Your administrator shows you a QR code, or gives you a domain and five words.");
                return;
            }
            StringBuilder d = new StringBuilder(s.getString("address"));
            if (!s.optString("user").isEmpty()) d.append("\nsigned in as ").append(s.getString("user"));
            if (!s.optString("exit").isEmpty()) d.append("\nall internet traffic goes through exit ").append(s.getString("exit"));
            JSONArray peers = s.optJSONArray("peers");
            int reachable = 0;
            if (peers != null) {
                for (int i = 0; i < peers.length(); i++) {
                    int ago = peers.getJSONObject(i).getInt("handshake_seconds_ago");
                    if (ago >= 0 && ago < 180) reachable++;
                }
                d.append("\n").append(reachable).append(" of ").append(peers.length()).append(" peers connected");
            }
            JSONArray groups = s.optJSONArray("groups");
            if (groups != null && groups.length() > 0) {
                d.append("\ngroups: ");
                for (int i = 0; i < groups.length(); i++) d.append(i > 0 ? ", " : "").append(groups.getString(i));
            }
            JSONArray failing = s.optJSONArray("posture_failing");
            if (failing != null) {
                for (int i = 0; i < failing.length(); i++) {
                    JSONObject f = failing.getJSONObject(i);
                    d.append("\nThis device needs attention: ").append(f.optString("reason"))
                            .append(" (check ").append(f.optString("check")).append(")");
                }
            }
            if (!s.optString("posture").isEmpty()) d.append("\nposture: ").append(s.getString("posture"));
            if (!s.getString("error").isEmpty()) d.append("\n").append(s.getString("error"));
            d.append("\nagent ").append(s.getString("version"));
            detail.setText(d);
            if (!running) state.setText("Disconnected");
            else if (s.getBoolean("login_required")) state.setText("Signed out: sign in again");
            else if (known && !s.getBoolean("approved")) state.setText("Waiting for approval: sign in");
            else if (failing != null && failing.length() > 0) state.setText("Limited: this device fails a check");
            else state.setText(reachable > 0 ? "Connected" : "Connecting");
            String login = Mobile.loginState();
            if (login.startsWith("done: ")) message.setText(login.substring(6));
            else if (login.startsWith("failed: ")) message.setText("Sign-in failed: " + login.substring(8));
        } catch (Exception e) {
            state.setText("Error");
            detail.setText(String.valueOf(e.getMessage()));
        }
    }



    /**
     * Shows the exit button when an exit is offered: it stops the one in use, or starts the first
     * offered (the agent applies the choice, the VPN service creates the VPN again with its routes).
     */
    private void showExit(JSONObject s, boolean running) throws org.json.JSONException {
        JSONArray exits = running ? s.optJSONArray("exits") : null;
        if (exits == null || exits.length() == 0) {
            exit.setVisibility(android.view.View.GONE);
            return;
        }
        JSONObject first = exits.getJSONObject(0), inUse = null;
        for (int i = 0; i < exits.length(); i++) {
            if (exits.getJSONObject(i).optBoolean("in_use")) inUse = exits.getJSONObject(i);
        }
        if (inUse != null) {
            exitChoice = "off";
            exit.setText("Stop sending all traffic through " + inUse.optString("via"));
        } else {
            exitChoice = first.optString("route");
            exit.setText("Send all traffic through " + first.optString("via"));
        }
        exit.setVisibility(android.view.View.VISIBLE);
    }

    private void chooseExit() {
        try {
            Mobile.setExit(Agent.stateDir(this), exitChoice);
            message.setText("off".equals(exitChoice) ? "Stopping the exit: a few seconds." : "Starting the exit: a few seconds.");
        } catch (Exception e) {
            message.setText("Exit: " + e.getMessage());
        }
    }

    /**
     * Finds the network record of the domain (asking the phone's DNS servers) and shows its
     * fingerprint. With a scanned QR code, the record's fingerprint must be the code's (expected),
     * and the code's words are filled in: Join, naming the domain, is left to the person.
     */
    private void lookUp(String domain, String expected, String words) {
        String d = domain.trim();
        if (d.isEmpty()) return;
        joinRecord = null;
        joinInfo.setVisibility(android.view.View.VISIBLE);
        joinInfo.setText("Looking up " + d + "...");
        joinWords.setVisibility(android.view.View.GONE);
        join.setVisibility(android.view.View.GONE);
        String dns = dnsServers();
        new Thread(() -> {
            String info, record = null;
            try {
                JSONObject r = new JSONObject(Mobile.lookupRecord(d, dns));
                String fingerprint = r.getString("fingerprint");
                if (expected == null) {
                    record = r.getString("record");
                    info = "Network " + d + " (" + r.getString("network") + ")\nfingerprint " + fingerprint
                            + "\nYour administrator can confirm it. If they name another, stop.";
                } else if (expected.equals(fingerprint)) {
                    record = r.getString("record");
                    info = "Network " + d + " (" + r.getString("network") + ")\nfingerprint " + fingerprint
                            + ", as the QR code says.";
                } else {
                    info = "The network found for " + d + " has the fingerprint " + fingerprint + ", the QR code says "
                            + expected + ": do not join. Tell your administrator.";
                }
            } catch (Exception e) {
                info = "No network found for " + d + ": " + e.getMessage();
            }
            String i = info, rec = record;
            runOnUiThread(() -> {
                joinRecord = rec;
                joinInfo.setText(i);
                int shown = rec == null ? android.view.View.GONE : android.view.View.VISIBLE;
                joinWords.setVisibility(shown);
                join.setVisibility(shown);
                join.setText(rec != null && words != null ? "Join " + d : "Join");
                if (rec != null && words != null) joinWords.setText(words);
            });
        }).start();
    }

    /** A scanned enrollment QR code: the domain, the network's fingerprint and the words. */
    private void scanned(String text) {
        try {
            JSONObject j = new JSONObject(Mobile.parseJoinCode(text));
            joinDomain.setText(j.getString("domain"));
            message.setText("");
            lookUp(j.getString("domain"), j.getString("fingerprint"), j.getString("words"));
        } catch (Exception e) {
            message.setText("That QR code cannot be used: " + e.getMessage());
        }
    }

    /** The DNS servers of the phone's active network, comma-separated. */
    private String dnsServers() {
        StringBuilder sb = new StringBuilder();
        try {
            android.net.ConnectivityManager cm = getSystemService(android.net.ConnectivityManager.class);
            android.net.LinkProperties lp = cm.getLinkProperties(cm.getActiveNetwork());
            if (lp != null) {
                for (java.net.InetAddress a : lp.getDnsServers()) sb.append(sb.length() > 0 ? "," : "").append(a.getHostAddress());
            }
        } catch (Exception ignored) {
        }
        return sb.toString();
    }

    private void joinWithWords(String words) {
        if (joinRecord == null || words.trim().isEmpty()) return;
        String record = joinRecord;
        message.setText("Joining (deriving the key from the words takes a few seconds)...");
        join.setEnabled(false);
        new Thread(() -> {
            String result;
            try {
                Mobile.enrollWords(Agent.stateDir(this), record, words, Agent.hostname(this));
                result = "Enrolled. Now connect.";
            } catch (Exception e) {
                result = "Joining failed: " + e.getMessage();
            }
            String r = result;
            runOnUiThread(() -> {
                message.setText(r);
                join.setEnabled(true);
                if (r.startsWith("Enrolled")) {
                    joinWords.setText("");
                    joinRecord = null;
                    joinInfo.setVisibility(android.view.View.GONE);
                }
                show();
            });
        }).start();
    }

    private void toggle() {
        try {
            if (new JSONObject(Mobile.status(Agent.stateDir(this))).getBoolean("running")) {
                Logs.i("Disconnect tapped");
                startService(new Intent(this, EntoVpnService.class).setAction(EntoVpnService.STOP));
                return;
            }
        } catch (Exception ignored) {
        }
        Logs.i("Connect tapped");
        Intent ask = VpnService.prepare(this);
        if (ask != null) startActivityForResult(ask, VPN_PERMISSION);
        else startVpn();
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == VPN_PERMISSION && result == RESULT_OK) startVpn();
        if (request == SCAN && result == RESULT_OK && data != null) scanned(data.getStringExtra(ScanActivity.EXTRA_TEXT));
    }

    private void startVpn() {
        startService(new Intent(this, EntoVpnService.class).setAction(EntoVpnService.START));
    }

    private void signIn() {
        message.setText("Starting sign-in...");
        new Thread(() -> {
            try {
                JSONObject l = new JSONObject(Mobile.loginStart(Agent.stateDir(this)));
                String url = l.optString("url"), code = l.optString("code");
                runOnUiThread(() -> {
                    message.setText("Sign in in the browser and check it shows the code " + code + ".\n" + url);
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                    } catch (android.content.ActivityNotFoundException e) {
                        message.setText("No browser found. Open " + url + " on any device and enter the code " + code + ".");
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> message.setText("Sign-in failed: " + e.getMessage()));
            }
        }).start();
    }

    /**
     * The admin page shows a code; approving it here (a request signed with the device's key, which
     * only this app holds) opens the page. Other apps on the phone reach the network, never its
     * administration, and nothing secret goes to the browser.
     */
    private void openAdminPage() {
        message.setText("Opening the admin page...");
        new Thread(() -> {
            try {
                String url = Mobile.adminPage(Agent.stateDir(this));
                runOnUiThread(() -> {
                    message.setText("Type the code the page shows below, then Approve.");
                    adminCode.setText("");
                    adminCode.setVisibility(android.view.View.VISIBLE);
                    adminApprove.setVisibility(android.view.View.VISIBLE);
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                    } catch (android.content.ActivityNotFoundException e) {
                        message.setText("No browser found. Open " + url + " in one, then type its code below.");
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> message.setText("Admin page: " + e.getMessage()));
            }
        }).start();
    }

    private void approveAdminPage(String code) {
        if (code.trim().isEmpty()) return;
        message.setText("Approving...");
        new Thread(() -> {
            String result;
            try {
                Mobile.adminApprove(Agent.stateDir(this), code.trim());
                result = "Approved: the page opens in a moment, for this phone only.";
            } catch (Exception e) {
                result = "Not approved: " + e.getMessage();
            }
            String r = result;
            runOnUiThread(() -> {
                message.setText(r);
                if (r.startsWith("Approved")) {
                    adminCode.setVisibility(android.view.View.GONE);
                    adminApprove.setVisibility(android.view.View.GONE);
                }
            });
        }).start();
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

    private TextView text(String s, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        return t;
    }

    private Button button(String label, android.view.View.OnClickListener l) {
        Button b = new Button(this);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextColor(Color.WHITE);
        b.setBackgroundColor(SIGNAL);
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(12);
        b.setLayoutParams(p);
        b.setOnClickListener(l);
        return b;
    }

    private int dp(int v) {
        return Math.round(v * getResources().getDisplayMetrics().density);
    }
}
