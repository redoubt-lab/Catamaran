package edu.njit.redoubt.logprivacy.activity;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;


import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;

import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import com.google.gson.Gson;

import org.bouncycastle.jcajce.provider.digest.MD5;
import org.bouncycastle.jcajce.provider.digest.SHA1;
import org.bouncycastle.jcajce.provider.digest.SHA256;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA512;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.lang.reflect.Field;


import java.security.MessageDigest;


import java.util.Arrays;
import java.util.List;


import edu.njit.redoubt.logprivacy.R;
import edu.njit.redoubt.logprivacy.common.Constant;
import edu.njit.redoubt.logprivacy.common.DatabaseHelper;
import edu.njit.redoubt.logprivacy.common.DeviceInformationUtils;
import edu.njit.redoubt.logprivacy.common.Utils;
import edu.njit.redoubt.logprivacy.modle.DeviceInformation;
import edu.njit.redoubt.logprivacy.modle.Rules;


public class MainActivity extends AppCompatActivity {

    private EditText clientIdEditText;

    private EditText ruleSerialNumberEditText;

    private EditText ruleGPSEditText;


    private EditText ruleSSIDEditText;

    private EditText ruleIMEIEditText;

    private EditText rulePhoneNumberEditText;

    private EditText ruleAAIDEditText;

    private EditText ruleBSSIDEditText;

    private EditText ruleEmailEditText;

    private EditText ruleMacAddressEditText;

    private EditText ruleIPv4EditText;

    private EditText ruleIPv6EditText;

    private Button autoFillOutButton;

    private Button saveConfigButton;

    private Integer PERMISSION_CODE=1;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            Process process =Runtime.getRuntime().exec("su");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        Window window = getWindow();
        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);
        window.setNavigationBarColor(ContextCompat.getColor(this, androidx.cardview.R.color.cardview_light_background));

        ActivityCompat.requestPermissions(MainActivity.this,
                new String[]{Manifest.permission.ACCESS_FINE_LOCATION,Manifest.permission.ACCESS_FINE_LOCATION, Manifest.permission.BLUETOOTH_CONNECT,
                        Manifest.permission.BLUETOOTH_SCAN},
                PERMISSION_CODE);

        initView();
        initRulesComponent();
        autoFillOutInit();
        saveConfigOnClickListenerInit();
        generalInfoInit();
        refreshEvents();
    }

    private void initView(){

        setContentView(R.layout.activity_main);

        clientIdEditText = findViewById(R.id.client_id_general_info);

        ruleSerialNumberEditText = findViewById(R.id.rule_serial_number);
        ruleGPSEditText = findViewById(R.id.rule_gps);
        ruleSSIDEditText = findViewById(R.id.rule_ssid);
        ruleIMEIEditText = findViewById(R.id.rule_imei);
        rulePhoneNumberEditText = findViewById(R.id.rule_phone_number);
        ruleAAIDEditText = findViewById(R.id.rule_aaid);

        ruleBSSIDEditText = findViewById(R.id.rule_bssid);
        ruleEmailEditText = findViewById(R.id.rule_email);
        ruleMacAddressEditText = findViewById(R.id.rule_mac_address);
        ruleIPv4EditText = findViewById(R.id.rule_IPv4);
        ruleIPv6EditText = findViewById(R.id.rule_IPv6);

        autoFillOutButton = findViewById(R.id.autoFillOut);
        saveConfigButton = findViewById(R.id.saveConfigButton);
    }
    private void initRulesComponent(){

        String rulesJson = DatabaseHelper
                .getInstance(this)
                .getConfigValueByKey(Constant.RulesConfigKey);

        Gson gson = new Gson();
        Rules rules = gson.fromJson(rulesJson, Rules.class);
        if(rules!=null) {
            ruleSerialNumberEditText.setText(String.join("\n", rules.getSerialNumber()));
            ruleGPSEditText.setText(String.join("\n", rules.getGps()));
            ruleSSIDEditText.setText(String.join("\n", rules.getSsid()));
            ruleIMEIEditText.setText(String.join("\n", rules.getImei()));
            rulePhoneNumberEditText.setText(String.join("\n", rules.getPhoneNumber()));
            ruleAAIDEditText.setText(String.join("\n", rules.getAaid()));

            ruleBSSIDEditText.setText(String.join("\n", rules.getBssid()));
            ruleEmailEditText.setText(String.join("\n", rules.getEmail()));
            ruleMacAddressEditText.setText(String.join("\n", rules.getMacAddress()));
            ruleIPv4EditText.setText(String.join("\n", rules.getIpv4()));
            ruleIPv6EditText.setText(String.join("\n", rules.getIpv6()));
        }
    }
    private void autoFillOutInit(){
        autoFillOutButton.setOnClickListener(view -> {
            ruleSerialNumberEditText.setText("");
            ruleGPSEditText.setText("");
            ruleSSIDEditText.setText("");
            ruleIMEIEditText.setText("");
            rulePhoneNumberEditText.setText("");
            ruleAAIDEditText.setText("");
            ruleBSSIDEditText.setText("");
            ruleEmailEditText.setText("");
            ruleMacAddressEditText.setText("");
            ruleIPv4EditText.setText("");
            ruleIPv6EditText.setText("");

            Toast.makeText(this, "Please wait!", Toast.LENGTH_SHORT).show();


            DeviceInformationUtils.updateDeviceSerialNumber(this);
            DeviceInformationUtils.updateDeviceIMEI(this);
            DeviceInformationUtils.updateDevicePhoneNumber(this);
            DeviceInformationUtils.updateSSID(this);

            DeviceInformationUtils.updateGPS(this,gps->{
                ruleGPSEditText.setText(gps);
            });

            DeviceInformationUtils.updateAAID(this,aaid->{
                runOnUiThread(()->{
                    ruleAAIDEditText.setText(aaid);
                });
            });

            DeviceInformationUtils.updateNetworkInfo(this);


            ruleIMEIEditText.setText(String.join("\n", DeviceInformation.getInstance(this).getIMEI()));
            rulePhoneNumberEditText.setText(String.join("\n", DeviceInformation.getInstance(this).getPhoneNumber()));
            ruleSerialNumberEditText.setText(DeviceInformation.getInstance(this).getDeviceSerialNumber());
            ruleSSIDEditText.setText(String.join("\n", DeviceInformation.getInstance(this).getAroundSSID()));
            ruleBSSIDEditText.setText(String.join("\n", DeviceInformation.getInstance(this).getAroundBSSID()));

            ruleMacAddressEditText.setText(String.join("\n", DeviceInformation.getInstance(this).getMacAddress()));
            ruleIPv4EditText.setText(String.join("\n", DeviceInformation.getInstance(this).getIpv4()));
            ruleIPv6EditText.setText(String.join("\n", DeviceInformation.getInstance(this).getIpv6()));

            Toast.makeText(this, "Complete!", Toast.LENGTH_SHORT).show();

        });
    }
    private void saveConfigOnClickListenerInit(){

        saveConfigButton.setOnClickListener(view -> {

            String clientID= clientIdEditText.getText().toString();
            DatabaseHelper
                    .getInstance(this)
                    .insertOrUpdateConfig(Constant.ClientID,clientID);


            String serialNumber = ruleSerialNumberEditText.getText().toString();
            String gps = ruleGPSEditText.getText().toString();
            String ssid = ruleSSIDEditText.getText().toString();
            String imei = ruleIMEIEditText.getText().toString();
            String phoneNumber = rulePhoneNumberEditText.getText().toString();
            String aaid = ruleAAIDEditText.getText().toString();

            String bssid = ruleBSSIDEditText.getText().toString();
            String email = ruleEmailEditText.getText().toString();
            String macAddress = ruleMacAddressEditText.getText().toString();
            String ipv4 = ruleIPv4EditText.getText().toString();
            String ipv6 = ruleIPv6EditText.getText().toString();


            Rules rules = new Rules();
            if(!Utils.isNullOrEmptyOrWhitespace(serialNumber)){
                rules.setSerialNumber(Arrays.asList(serialNumber.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(gps)){
                rules.setGps(Arrays.asList(gps.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(ssid)){
                rules.setSsid(Arrays.asList(ssid.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(imei)){
                rules.setImei(Arrays.asList(imei.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(phoneNumber)){
                rules.setPhoneNumber(Arrays.asList(phoneNumber.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(aaid)){
                rules.setAaid(Arrays.asList(aaid.split("\n")));
            }

            if(!Utils.isNullOrEmptyOrWhitespace(bssid)){
                rules.setBssid(Arrays.asList(bssid.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(email)){
                rules.setEmail(Arrays.asList(email.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(macAddress)){
                rules.setMacAddress(Arrays.asList(macAddress.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(ipv4)){
                rules.setIpv4(Arrays.asList(ipv4.split("\n")));
            }
            if(!Utils.isNullOrEmptyOrWhitespace(ipv6)){
                rules.setIpv6(Arrays.asList(ipv6.split("\n")));
            }

            DatabaseHelper
                    .getInstance(this)
                    .insertOrUpdateConfig(Constant.RulesConfigKey,new Gson().toJson(rules));
            enable_config(clientID,rules);
        });
    }

    private final String logMonitorConfig =
            "client_id={client_id}\n" +
                    "send_logs_to_server_url=http://127.0.0.1:6666/logs\n" +
                    "start_reading_log_threshold=256\n" +
                    "stop_reading_log_size=2048\n" +
                    "target_exe_path=/system/bin/app_process64\n" +
                    "target_file_path=/data/\n" +
                    "target_file_path=/storage/\n" +
                    "excluded_file_name=[eventfd]\n" +
                    "excluded_file_name= [eventfd]\n" +
                    "excluded_file_name=null\n" +
                    "excluded_file_name=0\n" +
                    "excluded_file_name=external.db-wal\n" +
                    "excluded_task_name=OomAdjuster\n" +
                    "excluded_task_name=ackgroundThread\n" +
                    "excluded_task_name=TaskSnapshotPer\n" +
                    "excluded_task_name=LazyTaskWriterT\n" +
                    "excluded_task_name=arch_disk_io_0\n" +
                    "excluded_task_name=SettingsProvide\n" +
                    "excluded_task_name=IpClient.wlan0\n" +
                    "excluded_task_name=FileObserver\n" +
                    "excluded_task_name=PowerStatsServi\n" +
                    "excluded_task_name=d.process.media\n" +
                    "excluded_task_name=android.bg\n" +
                    "target_file_suffix=.log\n" +
                    "target_file_suffix=.txt\n" +
                    "target_file_suffix=.text\n";

    private void enable_config(String clientID, Rules rules) {


        StringBuilder rule_config = new StringBuilder();
        Field[] fields = Rules.class.getDeclaredFields();
        for (Field field : fields) {
            try {
                field.setAccessible(true);
                List<String> values = (List<String>) field.get(rules);
                if (values != null) {
                    for (String value : values) {
                        rule_config.append(field.getName()).append("=").append(value).append("\n");
                        if(!field.getName().equals("gps")) {
                            rule_config.append(field.getName()).append("_MD5=").append(encrypt(value, "MD5")).append("\n");
                            rule_config.append(field.getName()).append("SHA1=").append(encrypt(value, "SHA-1")).append("\n");
                            rule_config.append(field.getName()).append("_SHA256=").append(encrypt(value, "SHA-256")).append("\n");
                            rule_config.append(field.getName()).append("_SHA512=").append(encrypt(value, "SHA-512")).append("\n");
                            rule_config.append(field.getName()).append("_SHA3_256=").append(encrypt(value, "SHA3-256")).append("\n");
                            rule_config.append(field.getName()).append("_SHA3_512=").append(encrypt(value, "SHA3-512")).append("\n");
                        }
                    }
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        String logMonitorConfigCommand = "echo \""+logMonitorConfig.replace("{client_id}",clientID)+"\" | cat >  /data/local/tmp/logmonitor/filter.config";
        String rulesCommand = "echo \""+rule_config+"\" | cat >  /data/local/tmp/logmonitor/rules.config";
        Utils.executeRootCommand(logMonitorConfigCommand);
        Utils.executeRootCommand(rulesCommand);
        Toast.makeText(this, "Save successfully", Toast.LENGTH_SHORT).show();
    }



    public static String encrypt(String value, String algorithm) {
        switch (algorithm.toUpperCase()) {
            case "MD5":
                return hashMD5(value);
            case "SHA-1":
                return hashSHA1(value);
            case "SHA-256":
                return hashSHA256(value);
            case "SHA-512":
                return hashSHA512(value);
            case "SHA3-256":
                return hashSHA3_256(value);
            case "SHA3-512":
                return hashSHA3_512(value);
            default:
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }
    }

    private static String hashMD5(String value) {
        MessageDigest digest = new MD5.Digest();
        byte[] hash = digest.digest(value.getBytes());
        return Hex.toHexString(hash);
    }

    private static String hashSHA1(String value) {
        MessageDigest digest = new SHA1.Digest();
        byte[] hash = digest.digest(value.getBytes());
        return Hex.toHexString(hash);
    }

    private static String hashSHA256(String value) {
        MessageDigest digest = new SHA256.Digest();
        byte[] hash = digest.digest(value.getBytes());
        return Hex.toHexString(hash);
    }

    private static String hashSHA512(String value) {
        MessageDigest digest = new SHA512.Digest();
        byte[] hash = digest.digest(value.getBytes());
        return Hex.toHexString(hash);
    }

    private static String hashSHA3_256(String value) {
        MessageDigest digest = new SHA3.Digest256();
        byte[] hash = digest.digest(value.getBytes());
        return Hex.toHexString(hash);
    }

    private static String hashSHA3_512(String value) {
        MessageDigest digest = new SHA3.Digest512();
        byte[] hash = digest.digest(value.getBytes());
        return Hex.toHexString(hash);
    }


    private void generalInfoInit(){

        String clientIDInDB = DatabaseHelper
                .getInstance(this)
                .getConfigValueByKey(Constant.ClientID);

        clientIdEditText.setText(clientIDInDB);
    }

    private void refreshEvents(){

    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);

        if (requestCode == PERMISSION_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_DENIED) {
                Toast.makeText(this, "Need Permission!", Toast.LENGTH_SHORT).show();
                finish();
            }
        }
    }
}