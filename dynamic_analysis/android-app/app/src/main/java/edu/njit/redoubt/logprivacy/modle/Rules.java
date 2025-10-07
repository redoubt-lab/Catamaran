package edu.njit.redoubt.logprivacy.modle;

import java.util.ArrayList;
import java.util.List;

public class Rules {
    private List<String> serialNumber = new ArrayList<>();
    private List<String> gps = new ArrayList<>();

    private List<String> ssid = new ArrayList<>();

    private List<String> imei = new ArrayList<>();

    private List<String> phoneNumber = new ArrayList<>();

    private List<String> aaid = new ArrayList<>();

    private List<String> bssid = new ArrayList<>();

    private List<String> email = new ArrayList<>();

    private List<String> macAddress = new ArrayList<>();

    private List<String> ipv4 = new ArrayList<>();

    private List<String> ipv6 = new ArrayList<>();

    public List<String> getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(List<String> serialNumber) {
        this.serialNumber = serialNumber;
    }

    public List<String> getGps() {
        return gps;
    }

    public void setGps(List<String> gps) {
        this.gps = gps;
    }

    public List<String> getSsid() {
        return ssid;
    }

    public void setSsid(List<String> ssid) {
        this.ssid = ssid;
    }

    public List<String> getImei() {
        return imei;
    }

    public void setImei(List<String> imei) {
        this.imei = imei;
    }

    public List<String> getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(List<String> phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public List<String> getAaid() {
        return aaid;
    }

    public void setAaid(List<String> aaid) {
        this.aaid = aaid;
    }


    public List<String> getBssid() {
        return bssid;
    }

    public void setBssid(List<String> bssid) {
        this.bssid = bssid;
    }

    public List<String> getEmail() {
        return email;
    }

    public void setEmail(List<String> email) {
        this.email = email;
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
