package com.entowire.ento.app;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.entowire.ento.mobile.Attestor;

import org.json.JSONArray;
import org.json.JSONObject;

import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * Android key attestation for the agent's posture reports. The Keystore makes a key in the phone's
 * secure hardware with the attestation challenge the agent derives from the device's WireGuard key,
 * and certifies it with a chain ending at Google's attestation root; the hardware writes into it
 * what it knows (verified boot, bootloader lock, patch levels, this app). The control nodes verify
 * that, not what the app says. Each report's time is signed with the key, which never leaves the
 * hardware, so a copy of the app's files on another phone has no attestation. The key is made
 * again when the challenge changes (a new enrollment), after a system update (its patch levels),
 * and every week (fresh certificates).
 */
final class Attest implements Attestor {
    private static final String ALIAS = "ento-attest";
    private static final long RENEW_MS = 7L * 24 * 3600 * 1000;

    private final SharedPreferences prefs;

    Attest(Context c) {
        prefs = c.getApplicationContext().getSharedPreferences("attest", Context.MODE_PRIVATE);
    }

    @Override
    public synchronized String attest(byte[] challenge, byte[] message) throws Exception {
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        String made = Base64.encodeToString(challenge, Base64.NO_WRAP) + " " + Build.FINGERPRINT;
        long now = System.currentTimeMillis();
        if (!ks.containsAlias(ALIAS) || !made.equals(prefs.getString("made", ""))
                || now - prefs.getLong("at", 0) > RENEW_MS || now < prefs.getLong("at", 0)) {
            make(challenge);
            prefs.edit().putString("made", made).putLong("at", now).apply();
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign((PrivateKey) ks.getKey(ALIAS, null));
        s.update(message);
        byte[] signature = s.sign();
        JSONArray chain = new JSONArray();
        for (Certificate c : ks.getCertificateChain(ALIAS)) chain.put(Base64.encodeToString(c.getEncoded(), Base64.NO_WRAP));
        return new JSONObject().put("chain", chain).put("signature", Base64.encodeToString(signature, Base64.NO_WRAP)).toString();
    }

    /** Makes the attested key (P-256, for signing only), replacing the one there was. */
    private static void make(byte[] challenge) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        g.initialize(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(challenge)
                .build());
        g.generateKeyPair();
    }
}
