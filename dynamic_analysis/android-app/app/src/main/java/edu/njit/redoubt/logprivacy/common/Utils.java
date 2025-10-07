package edu.njit.redoubt.logprivacy.common;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class Utils {
    public static String getFileName(String filePath) {
        Path path = Paths.get(filePath);
        return path.getFileName().toString();
    }

    public static String formatTimestamp(String timestampStr) {
        try {
            double timestamp = Double.parseDouble(timestampStr);
            long timeInMillis = (long) (timestamp * 1000);
            Date date = new Date(timeInMillis);

            SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy HH:mm:ss");
            sdf.setTimeZone(TimeZone.getTimeZone("America/New_York"));

            return sdf.format(date);
        } catch (NumberFormatException e) {
            return "Invalid timestamp format";
        }
    }


    public static boolean isNullOrEmptyOrWhitespace(String str) {
        return str == null || str.matches("\\s*");
    }

    public static String executeRootCommand(String command) {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"su", "-c", command});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            int read;
            char[] buffer = new char[4096];
            StringBuilder output = new StringBuilder();
            while ((read = reader.read(buffer)) > 0) {
                output.append(buffer, 0, read);
            }
            reader.close();
            process.waitFor();
            return output.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }
}
