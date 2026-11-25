package com.entowire.ento.app;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Typeface;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.entowire.ento.mobile.Mobile;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * The main screen, kept to what a person needs: whether the phone is connected, Connect or
 * Disconnect, Sign in or Sign out, an exit when one is offered, the admin page (admin and operator
 * devices), and why the device needs attention. Before joining: scan the QR code of the domain and
 * the words an administrator's admin page shows, or type them (`ento admin token --words`; phones
 * take no tokens). The technical details (address, groups, peers, routes, posture, versions) and
 * Send logs are on AdvancedActivity, behind a discreet link at the bottom. Sign-in approvals open
 * ApprovalActivity.
 *
 * A phone can be in several networks (0.60), all through its one VPN: once it is in more than one,
 * a row at the top picks the network the screen is about (its sign-in, admin page and state);
 * Connect, exits (the first network's) and approvals (every network's) are the phone's. "Join
 * another network" joins one more with its QR code or words, as the first was.
 */
public class MainActivity extends Activity {
    private static final int VPN_PERMISSION = 1;
    private static final int SCAN = 4;
    /** Where the identity provider returns a sign-in to the app (the manifest's filter). */
    static final String SIGNED_IN = "com.entowire.ento://signed-in";

    private final Handler handler = new Handler(Looper.getMainLooper());
    private TextView state, detail, message, typeInstead;
    private EditText adminCode, joinDomain, joinWords;
    private Button connect, account, adminPage, adminApprove, scan, lookUp, join, exit;
    private String exitChoice = ""; // what the exit button chooses: a route's name or "off"
    private boolean signedIn; // what the account button does: sign out (true) or sign in
    private String lastLogin = ""; // the sign-in outcome last shown, so it shows once
    private TextView joinInfo;
    private String joinRecord; // the network record found for joinDomain, for the words
    private String joinFor = ""; // the domain joinRecord was found for
    private String network = ""; // the network the screen is about: "" the first, else a joined one's domain
    private boolean joiningAnother; // the join controls are shown for another network
    private LinearLayout networks; // the row that picks the network, when the phone is in several
    private TextView joinAnother, leave;

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        LinearLayout root = new LinearLayout(this);

        LinearLayout header = new LinearLayout(this);
        header.setOrientation(LinearLayout.HORIZONTAL);
        header.setGravity(Gravity.CENTER_VERTICAL);
        ImageView mark = new ImageView(this);
        mark.setImageResource(R.drawable.mark);
        header.addView(mark);
        TextView word = Ui.text(this, "ento", 24, R.color.fg);
        word.setTypeface(Typeface.DEFAULT_BOLD);
        word.setPadding(dp(10), 0, 0, 0);
        header.addView(word);
        root.addView(header);

        networks = new LinearLayout(this);
        networks.setOrientation(LinearLayout.HORIZONTAL);
        networks.setPadding(0, dp(20), 0, 0);
        networks.setVisibility(View.GONE);
        android.widget.HorizontalScrollView scroll = new android.widget.HorizontalScrollView(this);
        scroll.setHorizontalScrollBarEnabled(false);
        scroll.addView(networks);
        root.addView(scroll);

        state = Ui.text(this, "", 26, R.color.fg);
        state.setTypeface(Typeface.DEFAULT_BOLD);
        state.setPadding(0, dp(36), 0, dp(4));
        root.addView(state);
        detail = Ui.text(this, "", 16, R.color.muted);
        root.addView(detail);

        // Joining: the QR code of the domain and the words, or both typed.
        scan = Ui.button(this, "Scan the QR code", v -> startActivityForResult(new Intent(this, ScanActivity.class), SCAN));
        ((LinearLayout.LayoutParams) scan.getLayoutParams()).topMargin = dp(28);
        root.addView(scan);
        typeInstead = Ui.link(this, "Type the domain and the words instead", v -> {
            joinDomain.setVisibility(View.VISIBLE);
            lookUp.setVisibility(View.VISIBLE);
            typeInstead.setVisibility(View.GONE);
            joinDomain.requestFocus();
        });
        root.addView(typeInstead);
        joinDomain = Ui.field(this, "Domain (e.g. example.com)", InputType.TYPE_TEXT_VARIATION_URI | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        joinDomain.setVisibility(View.GONE);
        root.addView(joinDomain);
        lookUp = Ui.button(this, "Find the network", v -> lookUp(joinDomain.getText().toString(), null, null));
        Ui.setPrimary(lookUp, false);
        lookUp.setVisibility(View.GONE);
        root.addView(lookUp);
        joinInfo = Ui.text(this, "", 15, R.color.fg);
        joinInfo.setPadding(0, dp(16), 0, 0);
        joinInfo.setVisibility(View.GONE);
        root.addView(joinInfo);
        joinWords = Ui.field(this, "The five words", InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        joinWords.setVisibility(View.GONE);
        root.addView(joinWords);
        join = Ui.button(this, "Join", v -> joinWithWords(joinWords.getText().toString()));
        join.setVisibility(View.GONE);
        root.addView(join);

        // Joined.
        connect = Ui.button(this, "Connect", v -> toggle());
        ((LinearLayout.LayoutParams) connect.getLayoutParams()).topMargin = dp(28);
        root.addView(connect);
        account = Ui.button(this, "Sign in", v -> {
            if (signedIn) signOut();
            else signIn();
        });
        root.addView(account);
        // An exit an administrator offers: all internet traffic through an office's gateway.
        exit = Ui.button(this, "", v -> chooseExit());
        Ui.setPrimary(exit, false);
        exit.setVisibility(View.GONE);
        root.addView(exit);
        adminPage = Ui.button(this, "Open the admin page", v -> openAdminPage());
        Ui.setPrimary(adminPage, false);
        root.addView(adminPage);
        adminCode = Ui.field(this, "Code the admin page shows", InputType.TYPE_TEXT_FLAG_CAP_CHARACTERS | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        adminCode.setVisibility(View.GONE);
        root.addView(adminCode);
        adminApprove = Ui.button(this, "Approve", v -> approveAdminPage(adminCode.getText().toString()));
        adminApprove.setVisibility(View.GONE);
        root.addView(adminApprove);
        joinAnother = Ui.link(this, "Join another network", v -> {
            joiningAnother = !joiningAnother;
            joinRecord = null;
            joinInfo.setVisibility(View.GONE);
            show();
        });
        joinAnother.setVisibility(View.GONE);
        root.addView(joinAnother);
        leave = Ui.link(this, "", v -> leaveNetwork());
        leave.setVisibility(View.GONE);
        root.addView(leave);
        message = Ui.text(this, "", 15, R.color.muted);
        message.setTextIsSelectable(true);
        message.setPadding(0, dp(16), 0, 0);
        root.addView(message);

        // The details and Send logs, out of the way.
        View spacer = new View(this);
        root.addView(spacer, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        TextView advanced = Ui.link(this, "Advanced", v -> startActivity(new Intent(this, AdvancedActivity.class)));
        advanced.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams ap = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        ap.gravity = Gravity.CENTER_HORIZONTAL;
        ap.topMargin = dp(24);
        root.addView(advanced, ap);

        setContentView(Ui.page(this, root));
        lastLogin = Mobile.loginState(); // an outcome from before this screen opened is not news
        finishSignIn(getIntent());

    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        finishSignIn(intent);
    }

    /** The end of a sign-in, as the identity provider returns it: handed to the control node. */
    private void finishSignIn(Intent intent) {
        Uri data = intent == null ? null : intent.getData();
        if (data == null || !Intent.ACTION_VIEW.equals(intent.getAction()) || !data.toString().startsWith(SIGNED_IN)) return;
        setIntent(new Intent(this, MainActivity.class)); // used once, not again on a rotation
        String address = data.toString();
        message.setText("Finishing the sign-in...");
        new Thread(() -> {
            String result = "";
            try {
                Mobile.loginFinish(Agent.stateDir(this), signingIn(), address);
            } catch (Exception e) {
                result = "Sign-in failed: " + e.getMessage();
            }
            String r = result;
            runOnUiThread(() -> {
                message.setText(r);
                show();
            });
        }).start();
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

    private static int shown(boolean b) {
        return b ? View.VISIBLE : View.GONE;
    }

    private void show() {
        try {
            String dir = Agent.stateDir(this);
            JSONArray nets = new JSONArray(Mobile.networks(dir));
            showNetworks(nets);
            JSONObject s = new JSONObject(Mobile.status(dir, network));
            boolean enrolled = s.getBoolean("enrolled"), running = s.getBoolean("running");
            // Joining: the phone's first network, or another one when asked for.
            boolean joining = !enrolled || joiningAnother;
            scan.setVisibility(shown(joining));
            if (!joining) {
                typeInstead.setVisibility(View.GONE);
                joinDomain.setVisibility(View.GONE);
                lookUp.setVisibility(View.GONE);
            } else if (joinDomain.getVisibility() == View.GONE && lookUp.getVisibility() == View.GONE) {
                typeInstead.setVisibility(View.VISIBLE);
            }
            if (!joining || joinRecord == null) {
                if (!joining) joinInfo.setVisibility(View.GONE);
                joinWords.setVisibility(View.GONE);
                join.setVisibility(View.GONE);
            }
            joinAnother.setVisibility(shown(enrolled));
            joinAnother.setText(joiningAnother ? "Cancel joining" : "Join another network");
            boolean joined = enrolled && !network.isEmpty();
            leave.setVisibility(shown(joined && !joiningAnother));
            if (joined) leave.setText("Leave " + network + " on this phone");
            connect.setVisibility(shown(enrolled));
            String login = Mobile.loginState();
            // A sign-in's outcome, once, as it happens: who is signed in shows above, so a plain
            // success only clears the sign-in's instructions; what it adds (no access, a failure) stays.
            if (!login.equals(lastLogin)) {
                lastLogin = login;
                if (login.startsWith("done: ")) message.setText(login.contains(", but ") ? login.substring(6) : "");
                else if (login.startsWith("failed: ")) message.setText("Sign-in failed: " + login.substring(8));
            }
            if (!enrolled) {
                account.setVisibility(View.GONE);
                adminPage.setVisibility(View.GONE);
                exit.setVisibility(View.GONE);
                state.setText("Join your network");
                detail.setText("Scan the QR code your administrator shows you, or type the domain and the five words they give you.");
                return;
            }

            boolean known = s.has("approved");
            boolean loginRequired = s.getBoolean("login_required");
            boolean waiting = known && !s.getBoolean("approved");
            String user = s.optString("user");
            JSONArray failing = s.optJSONArray("posture_failing");
            boolean limited = failing != null && failing.length() > 0;
            int reachable = 0;
            JSONArray peers = s.optJSONArray("peers");
            if (peers != null) {
                for (int i = 0; i < peers.length(); i++) {
                    int ago = peers.getJSONObject(i).getInt("handshake_seconds_ago");
                    if (ago >= 0 && ago < 180) reachable++;
                }
            }

            if (!running) state.setText("Disconnected");
            else if (loginRequired) state.setText("Sign in to continue");
            else if (waiting) state.setText("Waiting for approval");
            else if (limited) state.setText("Limited: this device fails a check");
            else state.setText(reachable > 0 ? "Connected" : "Connecting");

            StringBuilder d = new StringBuilder();
            if (running && !user.isEmpty()) line(d, "Signed in as " + user);
            if (running && !s.optString("exit").isEmpty()) line(d, "All internet traffic goes through " + s.getString("exit"));
            if (running && waiting && user.isEmpty()) line(d, "Sign in, or ask your administrator to approve this phone.");
            if (limited) {
                for (int i = 0; i < failing.length(); i++) line(d, "Needs attention: " + failing.getJSONObject(i).optString("reason"));
            }
            if (!s.getString("error").isEmpty()) line(d, s.getString("error"));
            detail.setText(d);

            connect.setText(running ? "Disconnect" : "Connect");
            Ui.setPrimary(connect, !running);
            // Sign in or out once connected: the sign-in runs through the network.
            signedIn = !user.isEmpty();
            account.setVisibility(shown(running));
            account.setText(signedIn ? "Sign out" : "Sign in");
            Ui.setPrimary(account, !signedIn && (loginRequired || waiting));
            if (joiningAnother) {
                state.setText("Join another network");
                detail.setText("Scan the QR code its administrator shows you, or type its domain and the five words they give you.");
            }
            boolean administers = running && s.optBoolean("administers", false);
            adminPage.setVisibility(shown(administers));
            if (!administers) {
                adminCode.setVisibility(View.GONE);
                adminApprove.setVisibility(View.GONE);
            }
            showExit(s, running && network.isEmpty()); // exits are the first network's
        } catch (Exception e) {
            state.setText("Error");
            detail.setText(String.valueOf(e.getMessage()));
        }
    }

    private static void line(StringBuilder d, String s) {
        if (d.length() > 0) d.append('\n');
        d.append(s);
    }

    /** The row of networks, shown once the phone is in more than one: tapping one shows it. */
    private void showNetworks(JSONArray nets) throws org.json.JSONException {
        boolean known = network.isEmpty();
        for (int i = 0; i < nets.length(); i++) {
            if (!nets.getJSONObject(i).optBoolean("first") && nets.getJSONObject(i).getString("domain").equals(network)) known = true;
        }
        if (!known) network = ""; // left meanwhile
        networks.setVisibility(shown(nets.length() > 1));
        if (nets.length() <= 1) {
            networks.removeAllViews();
            return;
        }
        StringBuilder key = new StringBuilder(network).append('|');
        for (int i = 0; i < nets.length(); i++) key.append(nets.getJSONObject(i).getString("domain")).append(',');
        if (key.toString().equals(networks.getTag())) return;
        networks.setTag(key.toString());
        networks.removeAllViews();
        for (int i = 0; i < nets.length(); i++) {
            JSONObject n = nets.getJSONObject(i);
            boolean first = n.optBoolean("first");
            String domain = n.getString("domain");
            String id = first ? "" : domain;
            Button b = Ui.button(this, domain.isEmpty() ? "First network" : domain, v -> {
                network = id;
                joiningAnother = false;
                message.setText("");
                show();
            });
            Ui.setPrimary(b, id.equals(network));
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
            lp.rightMargin = dp(8);
            networks.addView(b, lp);
        }
    }

    /** Leaves the joined network shown (the network keeps the phone until an administrator deletes it). */
    private void leaveNetwork() {
        String domain = network;
        if (domain.isEmpty()) return;
        new android.app.AlertDialog.Builder(this)
                .setTitle("Leave " + domain + "?")
                .setMessage("This phone stops reaching " + domain + ". Joining again needs new words from its administrator.")
                .setPositiveButton("Leave", (d, w) -> new Thread(() -> {
                    String result;
                    try {
                        Mobile.leave(Agent.stateDir(this), domain);
                        result = "Left " + domain + ".";
                    } catch (Exception e) {
                        result = "Could not leave: " + e.getMessage();
                    }
                    String r = result;
                    runOnUiThread(() -> {
                        message.setText(r);
                        network = "";
                        show();
                    });
                }).start())
                .setNegativeButton("Cancel", null)
                .show();
    }

    /**
     * Shows the exit button when an exit is offered: it stops the one in use, or starts the first
     * offered (the agent applies the choice, the VPN service creates the VPN again with its routes).
     */
    private void showExit(JSONObject s, boolean running) throws org.json.JSONException {
        JSONArray exits = running ? s.optJSONArray("exits") : null;
        if (exits == null || exits.length() == 0) {
            exit.setVisibility(View.GONE);
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
        exit.setVisibility(View.VISIBLE);
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
        joinInfo.setVisibility(View.VISIBLE);
        joinInfo.setText("Looking up " + d + "...");
        joinWords.setVisibility(View.GONE);
        join.setVisibility(View.GONE);
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
                joinFor = d.toLowerCase(java.util.Locale.ROOT);
                joinInfo.setText(i);
                int shown = rec == null ? View.GONE : View.VISIBLE;
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
        String record = joinRecord, domain = joinFor;
        boolean another = joiningAnother;
        message.setText("Joining (deriving the key from the words takes a few seconds)...");
        join.setEnabled(false);
        new Thread(() -> {
            String result;
            try {
                if (another) Mobile.joinWords(Agent.stateDir(this), domain, record, words, Agent.hostname(this));
                else Mobile.enrollWords(Agent.stateDir(this), record, words, Agent.hostname(this));
                result = "Enrolled. Connecting...";
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
                    joinInfo.setVisibility(View.GONE);
                    // Joined with words: connect and sign in, in one go (0.57). For a network's first
                    // administrator the sign-in is their account's setup, which ends signed in.
                    signInOnceConnected = true;
                    if (another) {
                        // Another network: the VPN is created again with its address (the service
                        // sees it), then the sign-in is that network's.
                        joiningAnother = false;
                        network = domain;
                        if (running()) signInWhenReady();
                        else toggle();
                    } else {
                        toggle();
                    }
                }
                show();
            });
        }).start();
    }

    private boolean running() {
        try {
            return new JSONObject(Mobile.status(Agent.stateDir(this), "")).getBoolean("running");
        } catch (Exception e) {
            return false;
        }
    }

    private void toggle() {
        try {
            if (new JSONObject(Mobile.status(Agent.stateDir(this), "")).getBoolean("running")) {
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
        if (signInOnceConnected) {
            signInOnceConnected = false;
            signInWhenReady();
        }
    }

    /** Set when the phone just joined with words: the sign-in starts once it is connected. */
    private boolean signInOnceConnected;

    /** Waits (at most a minute) until the agent runs and has its network map, then signs in. */
    private void signInWhenReady() {
        signInOnceConnected = false;
        message.setText("Connecting, then signing in...");
        String net = network;
        new Thread(() -> {
            for (int i = 0; i < 120; i++) {
                try {
                    JSONObject st = new JSONObject(Mobile.status(Agent.stateDir(this), net));
                    if (st.optBoolean("running") && st.has("approved")) {
                        if (st.optString("user").isEmpty()) runOnUiThread(this::signIn);
                        return;
                    }
                    Thread.sleep(500);
                } catch (InterruptedException e) {
                    return;
                } catch (Exception ignored) {
                }
            }
            runOnUiThread(() -> message.setText("Connected? Tap Sign in when the phone is."));
        }).start();
    }

    /** The network a sign-in started for, which its return to the app finishes (kept: the app may be closed meanwhile). */
    private String signingIn() {
        return getSharedPreferences("signin", MODE_PRIVATE).getString("network", "");
    }

    private void signIn() {
        message.setText("Starting sign-in...");
        String net = network;
        new Thread(() -> {
            try {
                getSharedPreferences("signin", MODE_PRIVATE).edit().putString("network", net).apply();
                JSONObject l = new JSONObject(Mobile.loginStart(Agent.stateDir(this), net, SIGNED_IN));
                String url = l.optString("url"), code = l.optString("code");
                runOnUiThread(() -> {
                    // No code: the sign-in returns to the app by itself. A code: an older control
                    // node, whose device sign-in asks for it on the page.
                    message.setText(code.isEmpty() ? "Sign in in the browser: you come back here when it is done."
                            : "Sign in in the browser, then type the code " + code + " when the page asks for it.");
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
                    } catch (android.content.ActivityNotFoundException e) {
                        message.setText(code.isEmpty() ? "No browser found: install one to sign in."
                                : "No browser found. Open " + url + " on any device and enter the code " + code + ".");
                    }
                });
            } catch (Exception e) {
                runOnUiThread(() -> message.setText("Sign-in failed: " + e.getMessage()));
            }
        }).start();
    }

    /** Signs the person out; the phone stays in the network as itself (what its own group allows). */
    private void signOut() {
        message.setText("Signing out...");
        new Thread(() -> {
            String result;
            try {
                result = Mobile.logout(Agent.stateDir(this), network)
                        ? "Signed out."
                        : "Signed out on this phone; the network hears of it once it can be reached.";
            } catch (Exception e) {
                result = "Sign-out failed: " + e.getMessage();
            }
            String r = result;
            runOnUiThread(() -> message.setText(r));
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
                String url = Mobile.adminPage(Agent.stateDir(this), network);
                runOnUiThread(() -> {
                    message.setText("Type the code the page shows below, then Approve.");
                    adminCode.setText("");
                    adminCode.setVisibility(View.VISIBLE);
                    adminApprove.setVisibility(View.VISIBLE);
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
                Mobile.adminApprove(Agent.stateDir(this), network, code.trim());
                result = "Approved: the page opens in a moment, for this phone only.";
            } catch (Exception e) {
                result = "Not approved: " + e.getMessage();
            }
            String r = result;
            runOnUiThread(() -> {
                message.setText(r);
                if (r.startsWith("Approved")) {
                    adminCode.setVisibility(View.GONE);
                    adminApprove.setVisibility(View.GONE);
                }
            });
        }).start();
    }

    private int dp(int v) {
        return Ui.dp(this, v);
    }
}
