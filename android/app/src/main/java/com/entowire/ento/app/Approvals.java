package com.entowire.ento.app;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;

import com.entowire.ento.mobile.Mobile;

import org.json.JSONArray;
import org.json.JSONObject;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.function.BooleanSupplier;

/**
 * Sign-in approvals: while the tunnel is up, asks the control plane (through the tunnel, so nothing
 * goes through Google's push service) for sign-ins of this phone's person that wait for approval,
 * and shows a notification for each; tapping it opens ApprovalActivity.
 */
final class Approvals {
    static final String CHANNEL = "approvals";
    private Approvals() {}

    /**
     * Runs until running says stop. The approvals come with the network map (ento 0.34): the
     * thread waits on the agent, which learns from each map how many approvals wait, and fetches
     * them only when that number changes, so the phone keeps no poll of its own open (each request
     * wakes the radio). Against older control nodes it asks itself, long polls of 25 s.
     */
    static void poll(Context c, String dir, BooleanSupplier running) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        nm.createNotificationChannel(new NotificationChannel(CHANNEL, "Sign-in approvals", NotificationManager.IMPORTANCE_HIGH));
        Set<String> shown = new HashSet<>();
        String lastError = ""; // logged once while it stays the same
        int count = -1; // what the map said last (-1: nothing yet)
        boolean supported = false;
        while (running.getAsBoolean()) {
            try {
                JSONObject w = new JSONObject(Mobile.waitApprovals(count, supported, 60));
                if (!w.optBoolean("seen")) continue; // no network map yet
                supported = w.optBoolean("supported");
                if (supported) {
                    int now = w.optInt("count");
                    // Waited a minute, nothing changed. While some wait, look anyway: one answered
                    // and another asked between two maps leave the number as it was.
                    if (now == count && now == 0) continue;
                    count = now;
                    show(c, nm, shown, new JSONArray(Mobile.pendingApprovals(dir, 0)));
                } else {
                    count = -1; // ask the map again at once next time, then ask ourselves
                    JSONArray list = new JSONArray(Mobile.pendingApprovals(dir, 25));
                    // The control plane answers at once while one is pending: do not ask in a loop.
                    if (show(c, nm, shown, list) == 0 && list.length() > 0) Thread.sleep(2000);
                }
                lastError = "";
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                if (!String.valueOf(e.getMessage()).equals(lastError)) Logs.w("approvals", e);
                lastError = String.valueOf(e.getMessage());
                count = -1;
                try {
                    Thread.sleep(5000);
                } catch (InterruptedException ie) {
                    return;
                }
            }
        }
    }

    /** Shows a notification for each new approval and takes away those gone; returns how many are new. */
    private static int show(Context c, NotificationManager nm, Set<String> shown, JSONArray list) throws Exception {
        Set<String> now = new HashSet<>();
        int added = 0;
        for (int i = 0; i < list.length(); i++) {
            JSONObject a = list.getJSONObject(i);
            String id = a.getString("id");
            now.add(id);
            if (shown.add(id)) {
                notify(c, nm, a);
                added++;
            }
        }
        for (String id : new ArrayList<>(shown)) {
            if (!now.contains(id)) { // answered elsewhere, or expired
                nm.cancel(id, 1);
                shown.remove(id);
            }
        }
        return added;
    }

    private static void notify(Context c, NotificationManager nm, JSONObject a) throws Exception {
        String id = a.getString("id");
        Intent open = new Intent(c, ApprovalActivity.class)
                .putExtra(ApprovalActivity.EXTRA, a.toString())
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(c, id.hashCode(), open,
                PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        long left = Instant.parse(a.getString("expires_at")).toEpochMilli() - System.currentTimeMillis();
        Notification.Builder b = new Notification.Builder(c, CHANNEL)
                .setSmallIcon(R.drawable.ic_launcher_foreground)
                .setContentTitle("Sign in to " + a.getString("device") + "?")
                .setContentText(a.getString("user") + " (" + a.getString("service") + "): tap to approve or deny")
                .setCategory(Notification.CATEGORY_STATUS)
                .setContentIntent(pi)
                .setAutoCancel(true)
                .setPublicVersion(new Notification.Builder(c, CHANNEL)
                        .setSmallIcon(R.drawable.ic_launcher_foreground)
                        .setContentTitle("A sign-in waits for your approval").build());
        if (left > 0) b.setTimeoutAfter(left);
        nm.notify(id, 1, b.build());
    }
}
