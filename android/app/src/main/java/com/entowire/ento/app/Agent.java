package com.entowire.ento.app;

import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.Context;
import android.os.Build;
import android.provider.Settings;

import com.entowire.ento.mobile.Mobile;

import org.json.JSONObject;

import java.io.File;
import java.util.Locale;

/** Where the agent keeps its state, and the name this device enrolls under. */
final class Agent {
    private Agent() {}

    private static Attest attestor; // set once (reportPosture)

    static String stateDir(Context c) {
        File d = new File(c.getFilesDir(), "ento");
        d.mkdirs();
        return d.getAbsolutePath();
    }

    /** The device's name as its owner set it (e.g. "Ana's Pixel" → "anas-pixel"), else its model. */
    static String hostname(Context c) {
        String name = Settings.Global.getString(c.getContentResolver(), Settings.Global.DEVICE_NAME);
        if (name == null || name.trim().isEmpty()) name = Build.MANUFACTURER + "-" + Build.MODEL;
        String s = name.toLowerCase(Locale.ROOT).replace("'", "");
        s = s.replaceAll("[^a-z0-9-]+", "-").replaceAll("-+", "-").replaceAll("^-|-$", "");
        return s.isEmpty() ? "android" : s;
    }

    /**
     * Gives the agent what only the app can read about the phone, for its posture report: Android's
     * release, SDK level and security patch level, whether storage is encrypted with a key the
     * user's credential protects (file-based encryption, ACTIVE_PER_USER, or full-disk ACTIVE;
     * ACTIVE_DEFAULT_KEY is not), and whether a screen lock is set; and the phone's key attestation
     * (Attest), from which the control nodes take verified boot and the patch levels instead.
     */
    static void reportPosture(Context c) {
        synchronized (Agent.class) {
            if (attestor == null) {
                attestor = new Attest(c);
                Mobile.setAttestor(attestor);
            }
        }
        try {
            JSONObject p = new JSONObject();
            p.put("os_version", Build.VERSION.RELEASE);
            p.put("sdk", Build.VERSION.SDK_INT);
            p.put("patch_level", Build.VERSION.SECURITY_PATCH);
            DevicePolicyManager dpm = c.getSystemService(DevicePolicyManager.class);
            if (dpm != null) {
                int e = dpm.getStorageEncryptionStatus();
                p.put("disk_encryption", e == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER
                        || e == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE);
            }
            KeyguardManager km = c.getSystemService(KeyguardManager.class);
            if (km != null) p.put("screen_lock", km.isDeviceSecure());
            // For the check-ins' fingerprint (hashed with the device's key, never sent as it is).
            String id = Settings.Secure.getString(c.getContentResolver(), Settings.Secure.ANDROID_ID);
            if (id != null) p.put("machine_id", id);
            Mobile.setPosture(p.toString());
        } catch (Exception e) {
            Logs.w("posture", e);
        }
    }
}
