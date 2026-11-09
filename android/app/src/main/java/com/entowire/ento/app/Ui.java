package com.entowire.ento.app;

import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Paint;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * The app's few building blocks in the website's colours (res/values/colors.xml, values-night/ when
 * the phone is dark): text, a primary and a secondary button, a discreet link, a text field.
 */
final class Ui {
    private Ui() {
    }

    static int color(Context c, int id) {
        return c.getColor(id);
    }

    static int dp(Context c, float v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    static TextView text(Context c, String s, int sp, int colorId) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color(c, colorId));
        t.setLineSpacing(0, 1.15f);
        return t;
    }

    /** A full-width button: primary (filled with the accent) or secondary (outlined). */
    static Button button(Context c, String label, android.view.View.OnClickListener l) {
        Button b = new Button(c);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(16);
        b.setStateListAnimator(null);
        b.setMinHeight(dp(c, 48));
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(c, 12);
        b.setLayoutParams(p);
        b.setOnClickListener(l);
        setPrimary(b, true);
        return b;
    }

    static void setPrimary(Button b, boolean primary) {
        Context c = b.getContext();
        GradientDrawable shape = new GradientDrawable();
        shape.setCornerRadius(dp(c, 8));
        if (primary) {
            shape.setColor(color(c, R.color.accent));
            b.setTextColor(color(c, R.color.accent_ink));
        } else {
            shape.setColor(color(c, R.color.bg));
            shape.setStroke(dp(c, 1), color(c, R.color.line));
            b.setTextColor(color(c, R.color.fg));
        }
        int ripple = (color(c, R.color.muted) & 0x00ffffff) | 0x40000000;
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(ripple), shape, null));
    }

    /** A small underlined text that acts as a link (Advanced, the typed way to join). */
    static TextView link(Context c, String s, android.view.View.OnClickListener l) {
        TextView t = text(c, s, 14, R.color.muted);
        t.setPaintFlags(t.getPaintFlags() | Paint.UNDERLINE_TEXT_FLAG);
        t.setPadding(0, dp(c, 12), 0, dp(c, 12));
        t.setOnClickListener(l);
        return t;
    }

    /**
     * The screen around root: scrolls, fills the window (so root can push a line to the bottom),
     * and keeps clear of the status and navigation bars and the keyboard (the window is edge to edge).
     */
    static android.widget.ScrollView page(Context c, LinearLayout root) {
        int pad = dp(c, 20), top = dp(c, 24);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, top, pad, pad);
        android.widget.ScrollView scroll = new android.widget.ScrollView(c);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(color(c, R.color.bg));
        scroll.addView(root, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            scroll.setOnApplyWindowInsetsListener((v, insets) -> {
                android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars() | android.view.WindowInsets.Type.ime());
                root.setPadding(pad + bars.left, top + bars.top, pad + bars.right, pad + bars.bottom);
                return android.view.WindowInsets.CONSUMED;
            });
        }
        return scroll;
    }

    static EditText field(Context c, String hint, int inputType) {
        EditText e = new EditText(c);
        e.setHint(hint);
        e.setTextColor(color(c, R.color.fg));
        e.setHintTextColor(color(c, R.color.muted));
        e.setInputType(InputType.TYPE_CLASS_TEXT | inputType);
        e.setLayoutParams(new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        return e;
    }
}
