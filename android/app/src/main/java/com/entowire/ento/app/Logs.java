package com.entowire.ento.app;

import android.util.Log;

import com.entowire.ento.mobile.Mobile;

/** The app's log lines: Android's log, and the app's log file (Send logs shares it). */
final class Logs {
    private Logs() {}

    static void i(String msg) {
        Log.i("ento", msg);
        write(msg);
    }

    static void w(String msg, Throwable t) {
        Log.w("ento", msg, t);
        write(t == null ? msg : msg + ": " + t);
    }

    private static void write(String msg) {
        try {
            Mobile.appLog(msg);
        } catch (Throwable ignored) { // the log never takes the app down
        }
    }
}
