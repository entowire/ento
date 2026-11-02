package com.entowire.ento.app;

import android.app.ActivityManager;
import android.app.Application;
import android.app.ApplicationExitInfo;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;

import com.entowire.ento.mobile.Mobile;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

/**
 * Starts the app's logs before anything else runs (Mobile.startLogs: logs/ento.log, and Go panics
 * into logs/crash-go.txt), writes Java crashes to logs/crash-java.txt before Android ends the app,
 * and records why the previous runs ended as Android tells it (Android 11 and later: a crash, a
 * native crash, not responding, low memory, killed by the system or the person) in logs/exits.txt,
 * with the system's trace when it was not responding. Send logs shares all of it.
 */
public class EntoApp extends Application {
    private static final long CRASH_MAX = 256 * 1024;

    static File logsDir(android.content.Context c) {
        File d = new File(c.getFilesDir(), "logs");
        d.mkdirs();
        return d;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        File dir = logsDir(this);
        try {
            Mobile.startLogs(dir.getAbsolutePath());
        } catch (Exception e) {
            Log.w("ento", "logs", e);
        }
        Logs.i("app " + versionName() + ", Android " + Build.VERSION.RELEASE + " (SDK " + Build.VERSION.SDK_INT + ", patch "
                + Build.VERSION.SECURITY_PATCH + "), " + Build.MANUFACTURER + " " + Build.MODEL);
        Thread.UncaughtExceptionHandler previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, e) -> {
            StringWriter sw = new StringWriter();
            e.printStackTrace(new PrintWriter(sw));
            append(new File(dir, "crash-java.txt"), "\n--- " + Instant.now() + " crash in thread " + thread.getName()
                    + " (app " + versionName() + ") ---\n" + sw + "\n");
            Logs.i("crash in thread " + thread.getName() + ": " + e);
            if (previous != null) previous.uncaughtException(thread, e);
        });
        if (Build.VERSION.SDK_INT >= 30) recordExits(dir);
    }

    /** Writes the reasons of the runs that ended since the last one recorded, oldest first. */
    private void recordExits(File dir) {
        try {
            SharedPreferences prefs = getSharedPreferences("logs", MODE_PRIVATE);
            long seen = prefs.getLong("exits_seen", 0), newest = seen;
            List<ApplicationExitInfo> exits = getSystemService(ActivityManager.class).getHistoricalProcessExitReasons(getPackageName(), 0, 16);
            StringBuilder sb = new StringBuilder();
            for (int i = exits.size() - 1; i >= 0; i--) {
                ApplicationExitInfo x = exits.get(i);
                if (x.getTimestamp() <= seen) continue;
                newest = Math.max(newest, x.getTimestamp());
                String line = Instant.ofEpochMilli(x.getTimestamp()) + " " + reason(x.getReason()) + " status=" + x.getStatus()
                        + " importance=" + x.getImportance() + " pss=" + x.getPss() + "kB"
                        + (x.getDescription() == null ? "" : " description=" + x.getDescription());
                sb.append(line).append('\n');
                Logs.i("previous run ended: " + line);
                // Not responding comes with a text trace; a native crash's is a binary tombstone, left
                // out (its status says the signal: 6 is an abort, as a Go panic ends).
                if (x.getReason() == ApplicationExitInfo.REASON_ANR) {
                    try (InputStream in = x.getTraceInputStream()) {
                        if (in != null) {
                            byte[] trace = new byte[64 * 1024];
                            int n = 0, r;
                            while (n < trace.length && (r = in.read(trace, n, trace.length - n)) > 0) n += r;
                            sb.append("  trace (first ").append(n).append(" bytes):\n").append(new String(trace, 0, n, StandardCharsets.UTF_8)).append('\n');
                        }
                    }
                }
            }
            if (sb.length() > 0) append(new File(dir, "exits.txt"), sb.toString());
            prefs.edit().putLong("exits_seen", newest).apply();
        } catch (Exception e) {
            Logs.w("exit reasons", e);
        }
    }

    private static String reason(int r) {
        switch (r) {
            case ApplicationExitInfo.REASON_ANR: return "NOT_RESPONDING";
            case ApplicationExitInfo.REASON_CRASH: return "CRASH";
            case ApplicationExitInfo.REASON_CRASH_NATIVE: return "CRASH_NATIVE";
            case ApplicationExitInfo.REASON_DEPENDENCY_DIED: return "DEPENDENCY_DIED";
            case ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE: return "EXCESSIVE_RESOURCE_USAGE";
            case ApplicationExitInfo.REASON_EXIT_SELF: return "EXIT_SELF";
            case ApplicationExitInfo.REASON_INITIALIZATION_FAILURE: return "INITIALIZATION_FAILURE";
            case ApplicationExitInfo.REASON_LOW_MEMORY: return "LOW_MEMORY";
            case ApplicationExitInfo.REASON_OTHER: return "OTHER";
            case ApplicationExitInfo.REASON_PERMISSION_CHANGE: return "PERMISSION_CHANGE";
            case ApplicationExitInfo.REASON_SIGNALED: return "SIGNALED";
            case ApplicationExitInfo.REASON_USER_REQUESTED: return "USER_REQUESTED";
            case ApplicationExitInfo.REASON_USER_STOPPED: return "USER_STOPPED";
            default: return "REASON_" + r;
        }
    }

    /** Appends to a file, emptying it first when it grew past CRASH_MAX. */
    static void append(File f, String s) {
        try {
            boolean keep = f.length() < CRASH_MAX;
            try (FileOutputStream out = new FileOutputStream(f, keep)) {
                out.write(s.getBytes(StandardCharsets.UTF_8));
            }
        } catch (Exception e) {
            Log.w("ento", "append " + f.getName(), e);
        }
    }

    private String versionName() {
        try {
            return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            return "?";
        }
    }
}
