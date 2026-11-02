package com.entowire.ento.app;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import com.entowire.ento.mobile.Mobile;
import com.entowire.ento.mobile.SocketProtector;

import org.json.JSONObject;

/**
 * Creates the VPN interface with the device's overlay address and the network's route, and hands
 * its file descriptor to the agent. Only the overlay network (and offices behind gateways) goes
 * through it, unless the phone uses an exit: then everything does (0.0.0.0/0), and IPv6, which the
 * VPN has none of, stays blocked. Its DNS server is the agent's resolver once the agent has one
 * that answers every name (the network's own names, the rest through the exit or the DNS servers of
 * the phone's other network, which the service gives it). WireGuard's own sockets are protected
 * (protect(int), called by the agent) so they never enter the tunnel, even towards endpoints inside
 * the overlay range.
 */
public class EntoVpnService extends VpnService implements SocketProtector {
    static final String START = "com.entowire.ento.START";
    static final String STOP = "com.entowire.ento.STOP";

    private volatile boolean running;
    // The routes' networks (offices behind gateways) the VPN was created with: Android fixes a VPN's
    // routes when it is created, so it is created again when the agent wants others.
    private volatile java.util.List<String> routes = new java.util.ArrayList<>();
    // The VPN's DNS server, the agent's resolver ("" for none).
    private volatile String dns = "";
    private volatile boolean watching;
    // Whether routes and dns were taken from the last session of this enrollment (remembered): the
    // VPN is created with them at once, instead of without them and again seconds later, when the
    // network map names them (the person saw it connect, disconnect and connect).
    private volatile boolean loaded;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? START : intent.getAction();
        Logs.i("VPN service: " + (intent == null ? "restarted by Android" : STOP.equals(action) ? "stop asked" : "start asked"));
        if (STOP.equals(action)) {
            running = false;
            Mobile.stop();
            stopSelf();
            return START_NOT_STICKY;
        }
        new Thread(this::start).start();
        return START_STICKY;
    }

    private void start() {
        try {
            String dir = Agent.stateDir(this);
            String net = Mobile.network(dir);
            if (net.isEmpty()) {
                Logs.w("not enrolled", null);
                stopSelf();
                return;
            }
            JSONObject n = new JSONObject(net);
            if (!loaded) {
                loaded = true;
                remembered(n.getString("address"));
            }
            String[] network = n.getString("network").split("/");
            Builder b = new Builder()
                    .setSession("ento")
                    .setMtu(n.getInt("mtu"))
                    .addAddress(n.getString("address"), n.getInt("prefix_bits"))
                    .addRoute(network[0], Integer.parseInt(network[1]));
            for (String r : routes) {
                String[] p = r.split("/");
                b.addRoute(p[0], Integer.parseInt(p[1]));
            }
            if (!dns.isEmpty()) b.addDnsServer(dns);
            ParcelFileDescriptor pfd = b.establish();
            if (pfd == null) {
                Logs.w("VPN permission not granted", null);
                stopSelf();
                return;
            }
            try {
                // The system routes the app's own sockets into the VPN only once the VPN network is
                // up; sockets opened before would reach the control nodes outside the tunnel.
                awaitVpnNetwork(n.getString("address"));
            } catch (Exception e) {
                pfd.close();
                throw e;
            }
            Agent.reportPosture(this);
            giveUpstreamDns();
            Mobile.start(dir, pfd.detachFd(), Agent.hostname(this), this); // the agent owns the interface now
            Logs.i("VPN up: routes " + routes + (dns.isEmpty() ? "" : ", DNS " + dns));
            if (!running) { // sign-in approvals for this phone's person, while the tunnel is up
                running = true;
                new Thread(() -> Approvals.poll(this, dir, () -> running), "approvals").start();
            }
            if (!watching) {
                watching = true;
                new Thread(() -> watchRoutes(dir), "routes").start();
            }
        } catch (Exception e) {
            Logs.w("start", e);
            stopSelf();
        }
    }

    /** Creates the VPN again when the routes (or the exit) the agent wants change (checked every 3 s). */
    private void watchRoutes(String dir) {
        while (running) {
            try {
                Thread.sleep(3000);
                giveUpstreamDns(); // the phone may have changed networks
                JSONObject s = new JSONObject(Mobile.status(dir));
                org.json.JSONArray a = s.optJSONArray("routes");
                java.util.List<String> want = new java.util.ArrayList<>();
                if (a != null) for (int i = 0; i < a.length(); i++) want.add(a.getString(i));
                String server = s.optString("dns");
                // Only once the network map arrived (a restarted agent knows no routes before it).
                if (!s.optBoolean("running") || !s.has("approved") || (want.equals(routes) && server.equals(dns))) continue;
                Logs.i("routes now " + want + (server.isEmpty() ? "" : ", DNS " + server) + ": creating the VPN again");
                routes = want;
                dns = server;
                remember(s.optString("address"));
                Mobile.stop();
                start();
            } catch (InterruptedException e) {
                return;
            } catch (Exception e) {
                Logs.w("routes", e);
            }
        }
        watching = false;
    }

    /** Loads the routes and DNS server the VPN last had for this enrollment (its address). */
    private void remembered(String address) {
        android.content.SharedPreferences p = getSharedPreferences("vpn", MODE_PRIVATE);
        if (!address.equals(p.getString("address", ""))) return;
        java.util.List<String> saved = new java.util.ArrayList<>();
        for (String r : p.getString("routes", "").split(",")) {
            if (r.matches("[0-9.]+/[0-9]+")) saved.add(r);
        }
        String server = p.getString("dns", "");
        routes = saved;
        dns = server.matches("[0-9.]+") ? server : "";
        if (!routes.isEmpty() || !dns.isEmpty()) Logs.i("VPN created with the last session's routes " + routes + (dns.isEmpty() ? "" : ", DNS " + dns));
    }

    /** Keeps the routes and DNS server the agent wants, for the next start. */
    private void remember(String address) {
        if (address.isEmpty()) return;
        getSharedPreferences("vpn", MODE_PRIVATE).edit().putString("address", address)
                .putString("routes", String.join(",", routes)).putString("dns", dns).apply();
    }

    /**
     * Gives the agent the IPv4 DNS servers of the network the phone uses beside the VPN (a validated
     * one first): its resolver asks them for names that are neither the network's nor an exit's.
     */
    private void giveUpstreamDns() {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        String best = "", any = "";
        for (Network net : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(net);
            LinkProperties props = cm.getLinkProperties(net);
            if (caps == null || props == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            StringBuilder sb = new StringBuilder();
            for (java.net.InetAddress a : props.getDnsServers()) {
                if (a instanceof java.net.Inet4Address) sb.append(sb.length() > 0 ? "," : "").append(a.getHostAddress());
            }
            if (sb.length() == 0) continue;
            if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) && best.isEmpty()) best = sb.toString();
            if (any.isEmpty()) any = sb.toString();
        }
        Mobile.setUpstreamDNS(best.isEmpty() ? any : best);
    }

    /** Waits (at most 5 s) until the system lists a VPN network carrying the device's address. */
    private void awaitVpnNetwork(String address) throws InterruptedException {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        for (int i = 0; i < 50; i++) {
            for (Network net : cm.getAllNetworks()) {
                NetworkCapabilities caps = cm.getNetworkCapabilities(net);
                LinkProperties props = cm.getLinkProperties(net);
                if (caps == null || props == null || !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue;
                for (LinkAddress a : props.getLinkAddresses()) {
                    if (a.getAddress().getHostAddress().equals(address)) return;
                }
            }
            Thread.sleep(100);
        }
        Logs.w("VPN network not reported after 5 s; starting anyway", null);
    }

    @Override
    public void onRevoke() {
        Logs.i("VPN revoked (another VPN app, or the person in Android's settings)");
        running = false;
        Mobile.stop();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        Logs.i("VPN service destroyed");
        running = false;
        Mobile.stop();
        super.onDestroy();
    }
}
