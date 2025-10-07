package edu.njit.redoubt.logprivacy.common;

import android.content.Context;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.StrictMode;

import com.google.android.gms.ads.identifier.AdvertisingIdClient;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import edu.njit.redoubt.logprivacy.modle.DeviceInformation;

public class DeviceInformationUtils {

    public static void updateDeviceSerialNumber(Context context) {
        String deviceSerialNumber = Utils.executeRootCommand("getprop ro.serialno").replace("\n","");
        DeviceInformation.getInstance(context).setDeviceSerialNumber(deviceSerialNumber);
    }

    public static void updateDeviceIMEI(Context context) {

    }

    public static void updateDevicePhoneNumber(Context context) {

    }


    public static void updateAAID(Context context, Consumer<String> consumer) {
        new Thread(()->{
            try {
                AdvertisingIdClient.Info adInfo = AdvertisingIdClient.getAdvertisingIdInfo(context);
                DeviceInformation.getInstance(context).setAaid(adInfo.getId());
                consumer.accept(DeviceInformation.getInstance(context).getAaid());
            }catch (Exception e){
                e.printStackTrace();
            }
        }).start();
    }

    public static void updateGPS(Context context, Consumer<String> consumer){
        LocationManager locationManager = (LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        LocationListener locationListener = location -> {
            double latitude = location.getLatitude();
            double longitude = location.getLongitude();
            DeviceInformation.getInstance(context).setGps(String.format("%.3f", latitude)+","+String.format("%.3f", longitude));
            consumer.accept(DeviceInformation.getInstance(context).getGps());
        };

        String[] providers = {LocationManager.PASSIVE_PROVIDER};

        for (String provider : providers) {
            locationManager.requestLocationUpdates(provider, 0, 0, locationListener);
        }
    }

    public static void updateSSID(Context context) {
        Set<String> ssidSet = new HashSet<>();
        Set<String> bssidSet = new HashSet<>();
        WifiManager wifiManager = (WifiManager) context.getSystemService(Context.WIFI_SERVICE);
        List<ScanResult> results = wifiManager.getScanResults();
        for (ScanResult result : results) {
            String ssid = result.SSID;
            String bssid = result.BSSID;
            if(ssid!=null && !ssid.equals("")) {
                ssidSet.add(ssid);
            }
            if(bssid!=null && !bssid.equals("")) {
                bssidSet.add(bssid);
            }

        }
        DeviceInformation.getInstance(context).setAroundSSID(new ArrayList<>(ssidSet));
        DeviceInformation.getInstance(context).setAroundBSSID(new ArrayList<>(bssidSet));
    }

    public static void updateNetworkInfo(Context context){
        Set<String> macAddresses = new HashSet<>();
        Set<String> ipv4Addresses = new HashSet<>();
        Set<String> ipv6Addresses = new HashSet<>();

        getAddresses(macAddresses,ipv4Addresses,ipv6Addresses);

        macAddresses.add((((WifiManager) context.getSystemService(Context.WIFI_SERVICE)).getConnectionInfo().getMacAddress()).replace("\n",""));
        macAddresses.add(Utils.executeRootCommand("cat /sys/class/net/wlan0/address").replace("\n",""));
        macAddresses.add(Utils.executeRootCommand("settings get secure bluetooth_address").replace("\n",""));

        DeviceInformation.getInstance(context).setMacAddress(new ArrayList<>(macAddresses));
        String pubIP =getPublicIPAddress();
        if(!"".equals(pubIP)) {
            ipv4Addresses.add(pubIP);
        }
        DeviceInformation.getInstance(context).setIpv4(new ArrayList<>(ipv4Addresses));
        ipv6Addresses.remove("::1");
        DeviceInformation.getInstance(context).setIpv6(new ArrayList<>(ipv6Addresses));
    }


    private static void getAddresses(Set<String> macAddresses, Set<String> ipv4Addresses, Set<String> ipv6Addresses) {
        Pattern macPattern = Pattern.compile("HWaddr ([0-9a-fA-F:]{17})");
        Pattern ipv4Pattern = Pattern.compile("inet addr:([0-9.]+)");
        Pattern ipv6Pattern = Pattern.compile("inet6 addr: ([0-9a-fA-F:]+)");

        for (String line : Utils.executeRootCommand("ifconfig").split("\n")) {
            Matcher macMatcher = macPattern.matcher(line);
            Matcher ipv4Matcher = ipv4Pattern.matcher(line);
            Matcher ipv6Matcher = ipv6Pattern.matcher(line);

            if (macMatcher.find()) {
                macAddresses.add(macMatcher.group(1));
            }

            if (ipv4Matcher.find()) {
                ipv4Addresses.add(ipv4Matcher.group(1));
            }

            if (ipv6Matcher.find()) {
                ipv6Addresses.add(ipv6Matcher.group(1));
            }
        }
    }

    public static String getPublicIPAddress() {
        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder().permitAll().build();
        StrictMode.setThreadPolicy(policy);
        String publicIP = "";
        try {
            URL url = new URL("https://api.ipify.org");
            HttpURLConnection urlConnection = (HttpURLConnection) url.openConnection();
            urlConnection.setConnectTimeout(2000);
            urlConnection.setReadTimeout(2000);
            try {
                BufferedReader in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));
                publicIP = in.readLine();
                in.close();
            } finally {
                urlConnection.disconnect();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicIP.replace("\n","").replace(" ","");
    }



}
