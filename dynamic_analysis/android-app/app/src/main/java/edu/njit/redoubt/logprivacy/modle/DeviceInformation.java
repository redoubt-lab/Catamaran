package edu.njit.redoubt.logprivacy.modle;

import android.content.Context;

import java.util.ArrayList;
import java.util.List;


public class DeviceInformation {
    private List<String> IMEI = new ArrayList<>();

    private List<String> phoneNumber = new ArrayList<>();

    private List<String> aroundSSID = new ArrayList<>();

    private List<String> aroundBSSID = new ArrayList<>();

    private List<String> macAddress = new ArrayList<>();

    private List<String> ipv4 = new ArrayList<>();

    private List<String> ipv6 = new ArrayList<>();

    private String realMacAddress;

    private String gps;

    private String aaid;

    private String deviceSerialNumber;

    private String simSerialNumber;

    private Context context;

    private static DeviceInformation instance;

    private DeviceInformation(Context context) {
        this.context = context;
    }

    public static synchronized DeviceInformation getInstance(Context context) {
        if (instance == null) {
            instance = new DeviceInformation(context.getApplicationContext());
        }
        return instance;
    }

    public String getRealMacAddress() {
        return realMacAddress;
    }

    public void setRealMacAddress(String realMacAddress) {
        this.realMacAddress = realMacAddress;
    }

    public List<String> getIMEI() {
        return IMEI;
    }

    public void setIMEI(List<String> IMEI) {
        this.IMEI = IMEI;
    }

    public List<String> getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(List<String> phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public List<String> getAroundSSID() {
        return aroundSSID;
    }

    public void setAroundSSID(List<String> aroundSSID) {
        this.aroundSSID = aroundSSID;
    }

    public String getGps() {
        return gps;
    }

    public void setGps(String gps) {
        this.gps = gps;
    }

    public String getAaid() {
        return aaid;
    }

    public void setAaid(String aaid) {
        this.aaid = aaid;
    }
    public String getDeviceSerialNumber() {
        return deviceSerialNumber;
    }

    public void setDeviceSerialNumber(String deviceSerialNumber) {
        this.deviceSerialNumber = deviceSerialNumber;
    }

    public String getSimSerialNumber() {
        return simSerialNumber;
    }

    public void setSimSerialNumber(String simSerialNumber) {
        this.simSerialNumber = simSerialNumber;
    }

    public List<String> getAroundBSSID() {
        return aroundBSSID;
    }

    public void setAroundBSSID(List<String> aroundBSSID) {
        this.aroundBSSID = aroundBSSID;
    }

    public List<String> getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(List<String> macAddress) {
        this.macAddress = macAddress;
    }

    public List<String> getIpv4() {
        return ipv4;
    }

    public void setIpv4(List<String> ipv4) {
        this.ipv4 = ipv4;
    }

    public List<String> getIpv6() {
        return ipv6;
    }

    public void setIpv6(List<String> ipv6) {
        this.ipv6 = ipv6;
    }
}
