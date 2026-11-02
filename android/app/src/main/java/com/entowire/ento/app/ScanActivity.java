package com.entowire.ento.app;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.ImageFormat;
import android.graphics.Matrix;
import android.graphics.SurfaceTexture;
import android.hardware.camera2.CameraAccessException;
import android.hardware.camera2.CameraCaptureSession;
import android.hardware.camera2.CameraCharacteristics;
import android.hardware.camera2.CameraDevice;
import android.hardware.camera2.CameraManager;
import android.hardware.camera2.CaptureRequest;
import android.hardware.camera2.params.StreamConfigurationMap;
import android.media.Image;
import android.media.ImageReader;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.util.Size;
import android.view.Gravity;
import android.view.Surface;
import android.view.TextureView;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.LuminanceSource;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.ReaderException;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Locale;
import java.util.Map;

/**
 * Reads an enrollment QR code with the camera (the domain, the network's fingerprint and the
 * words, as an administrator's admin page or `ento admin token --words --qr` shows them) and
 * returns its text as EXTRA_TEXT. Frames go from the camera to ZXing's decoder on a background
 * thread and are dropped at once: nothing is stored. The camera permission is asked for here, when
 * someone scans, and never used otherwise.
 */
public class ScanActivity extends Activity {
    static final String EXTRA_TEXT = "text";
    private static final int CAMERA_PERMISSION = 3;
    private static final String PREFIX = "ENTO1:";

    private TextureView view;
    private TextView hint;
    // The camera's callbacks run on the background thread; the rest on the main thread.
    private HandlerThread thread;
    private volatile Handler background; // null while paused
    private volatile CameraDevice camera;
    private volatile CameraCaptureSession session;
    private ImageReader reader;
    private boolean opening;
    private Size size;
    private int sensorOrientation;
    private volatile boolean done;
    private final QRCodeReader qr = new QRCodeReader();
    private final Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        hints.put(DecodeHintType.POSSIBLE_FORMATS, EnumSet.of(BarcodeFormat.QR_CODE));
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.BLACK);
        view = new TextureView(this);
        root.addView(view, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);
        bar.setBackgroundColor(Color.argb(0xcc, 0x0b, 0x0c, 0x0e));
        int pad = Math.round(20 * getResources().getDisplayMetrics().density);
        bar.setPadding(pad, pad, pad, pad * 2);
        hint = new TextView(this);
        hint.setText("Point the camera at the QR code your administrator shows.");
        hint.setTextColor(Color.rgb(0xe9, 0xea, 0xec));
        hint.setTextSize(16);
        bar.addView(hint);
        Button cancel = new Button(this);
        cancel.setText("Cancel");
        cancel.setAllCaps(false);
        cancel.setOnClickListener(v -> finish());
        bar.addView(cancel);
        root.addView(bar, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM));
        // The window is edge to edge: keep the bar clear of the navigation bar.
        if (Build.VERSION.SDK_INT >= 30) {
            root.setOnApplyWindowInsetsListener((v, insets) -> {
                android.graphics.Insets bars = insets.getInsets(WindowInsets.Type.systemBars());
                bar.setPadding(pad + bars.left, pad, pad + bars.right, pad + bars.bottom);
                return WindowInsets.CONSUMED;
            });
        }
        setContentView(root);
    }

    @Override
    protected void onResume() {
        super.onResume();
        thread = new HandlerThread("scan");
        thread.start();
        background = new Handler(thread.getLooper());
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, CAMERA_PERMISSION);
            return;
        }
        whenViewReady();
    }

    @Override
    protected void onPause() {
        closeCamera();
        thread.quitSafely();
        thread = null;
        background = null;
        super.onPause();
    }

    @Override
    public void onRequestPermissionsResult(int request, String[] permissions, int[] results) {
        if (request != CAMERA_PERMISSION) return;
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            if (background != null) whenViewReady();
        } else {
            hint.setText("Without the camera, type the domain and the words instead.");
        }
    }

    private void whenViewReady() {
        if (view.isAvailable()) {
            openCamera();
            return;
        }
        view.setSurfaceTextureListener(new TextureView.SurfaceTextureListener() {
            @Override
            public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) {
                if (background != null) openCamera();
            }

            @Override
            public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) {
                fitPreview();
            }

            @Override
            public boolean onSurfaceTextureDestroyed(SurfaceTexture st) {
                return true;
            }

            @Override
            public void onSurfaceTextureUpdated(SurfaceTexture st) {
            }
        });
    }

    /** Opens the back camera (else any) with frames near 1280x720 for the decoder. */
    private void openCamera() {
        if (opening) return;
        opening = true;
        CameraManager m = getSystemService(CameraManager.class);
        try {
            String id = null;
            for (String c : m.getCameraIdList()) {
                Integer facing = m.getCameraCharacteristics(c).get(CameraCharacteristics.LENS_FACING);
                if (id == null || (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK)) id = c;
                if (facing != null && facing == CameraCharacteristics.LENS_FACING_BACK) break;
            }
            if (id == null) {
                hint.setText("This phone has no camera: type the domain and the words instead.");
                return;
            }
            CameraCharacteristics chars = m.getCameraCharacteristics(id);
            Integer orientation = chars.get(CameraCharacteristics.SENSOR_ORIENTATION);
            sensorOrientation = orientation == null ? 90 : orientation;
            StreamConfigurationMap map = chars.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP);
            size = choose(map.getOutputSizes(ImageFormat.YUV_420_888));
            reader = ImageReader.newInstance(size.getWidth(), size.getHeight(), ImageFormat.YUV_420_888, 2);
            reader.setOnImageAvailableListener(this::decode, background);
            m.openCamera(id, new CameraDevice.StateCallback() {
                @Override
                public void onOpened(CameraDevice c) {
                    if (background == null) { // paused meanwhile
                        c.close();
                        return;
                    }
                    camera = c;
                    startPreview();
                }

                @Override
                public void onDisconnected(CameraDevice c) {
                    c.close();
                    camera = null;
                }

                @Override
                public void onError(CameraDevice c, int error) {
                    c.close();
                    camera = null;
                    runOnUiThread(() -> hint.setText("The camera failed (" + error + "): type the domain and the words instead."));
                }
            }, background);
        } catch (CameraAccessException | SecurityException e) {
            Logs.w("camera", e);
            hint.setText("The camera is not available: type the domain and the words instead.");
        }
    }

    /** The output size closest to 1280x720 in pixels, at most 1920 wide: enough for a QR code on a screen. */
    private static Size choose(Size[] sizes) {
        Size best = sizes[0];
        for (Size s : sizes) {
            if (s.getWidth() > 1920) continue;
            if (best.getWidth() > 1920 || Math.abs(s.getWidth() * s.getHeight() - 1280 * 720) < Math.abs(best.getWidth() * best.getHeight() - 1280 * 720)) {
                best = s;
            }
        }
        return best;
    }

    @SuppressWarnings("deprecation") // createCaptureSession(List...) is the form API 26 has
    private void startPreview() {
        try {
            SurfaceTexture st = view.getSurfaceTexture();
            st.setDefaultBufferSize(size.getWidth(), size.getHeight());
            Surface preview = new Surface(st);
            CaptureRequest.Builder b = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW);
            b.addTarget(preview);
            b.addTarget(reader.getSurface());
            b.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE);
            camera.createCaptureSession(Arrays.asList(preview, reader.getSurface()), new CameraCaptureSession.StateCallback() {
                @Override
                public void onConfigured(CameraCaptureSession s) {
                    if (camera == null) return;
                    session = s;
                    try {
                        s.setRepeatingRequest(b.build(), null, background);
                    } catch (CameraAccessException | IllegalStateException e) {
                        Logs.w("camera preview", e);
                    }
                }

                @Override
                public void onConfigureFailed(CameraCaptureSession s) {
                    runOnUiThread(() -> hint.setText("The camera could not start: type the domain and the words instead."));
                }
            }, background);
            runOnUiThread(this::fitPreview);
        } catch (CameraAccessException | IllegalStateException e) {
            Logs.w("camera preview", e);
        }
    }

    /** Fills the view with the preview without stretching it (the edges are cut off instead). */
    private void fitPreview() {
        if (size == null || view.getWidth() == 0) return;
        boolean turned = sensorOrientation == 90 || sensorOrientation == 270; // the activity is portrait
        float content = turned ? (float) size.getHeight() / size.getWidth() : (float) size.getWidth() / size.getHeight();
        float vw = view.getWidth(), vh = view.getHeight(), aspect = vw / vh;
        Matrix m = new Matrix();
        if (aspect < content) m.setScale(content / aspect, 1f, vw / 2, vh / 2);
        else m.setScale(1f, aspect / content, vw / 2, vh / 2);
        view.setTransform(m);
    }

    /** Decodes the latest frame (its luminance plane), also inverted (light modules on dark). */
    private void decode(ImageReader r) {
        Image img = r.acquireLatestImage();
        if (img == null) return;
        try {
            if (done) return;
            int w = img.getWidth(), h = img.getHeight();
            Image.Plane y = img.getPlanes()[0];
            ByteBuffer buf = y.getBuffer();
            int stride = y.getRowStride();
            byte[] data = new byte[w * h];
            for (int row = 0; row < h; row++) {
                buf.position(row * stride);
                buf.get(data, row * w, w);
            }
            LuminanceSource src = new PlanarYUVLuminanceSource(data, w, h, 0, 0, w, h, false);
            String text = read(src);
            if (text == null) text = read(src.invert());
            if (text == null) return;
            if (!text.trim().toUpperCase(Locale.ROOT).startsWith(PREFIX)) {
                runOnUiThread(() -> hint.setText("That QR code is not an ento enrollment code. Point the camera at the one your administrator shows."));
                return;
            }
            done = true;
            String found = text.trim();
            runOnUiThread(() -> {
                setResult(RESULT_OK, new Intent().putExtra(EXTRA_TEXT, found));
                finish();
            });
        } catch (RuntimeException e) {
            Logs.w("scan", e);
        } finally {
            img.close();
        }
    }

    private String read(LuminanceSource src) {
        try {
            return qr.decode(new BinaryBitmap(new HybridBinarizer(src)), hints).getText();
        } catch (ReaderException e) {
            return null;
        } finally {
            qr.reset();
        }
    }

    private void closeCamera() {
        opening = false;
        if (session != null) {
            session.close();
            session = null;
        }
        if (camera != null) {
            camera.close();
            camera = null;
        }
        if (reader != null) {
            reader.close();
            reader = null;
        }
    }
}
