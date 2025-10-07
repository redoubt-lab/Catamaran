package edu.njit.redoubtlab.element;

public class LogcatMetaData {
    public static final String CLASS_NAME = "android.util.Log";

    public static String getMethodName(String level, Boolean isContainException) {
        String methodName;
        switch (level.toLowerCase()) {
            case "v":
                methodName = isContainException ? "<android.util.Log: int v(java.lang.String,java.lang.String,java.lang.Throwable)>"
                        : "<android.util.Log: int v(java.lang.String,java.lang.String)>";
                break;
            case "d":
                methodName = isContainException ? "<android.util.Log: int d(java.lang.String,java.lang.String,java.lang.Throwable)>"
                        : "<android.util.Log: int d(java.lang.String,java.lang.String)>";
                break;
            case "i":
                methodName = isContainException ? "<android.util.Log: int i(java.lang.String,java.lang.String,java.lang.Throwable)>"
                        : "<android.util.Log: int i(java.lang.String,java.lang.String)>";
                break;
            case "w":
                methodName = isContainException ? "<android.util.Log: int w(java.lang.String,java.lang.String,java.lang.Throwable)>"
                        : "<android.util.Log: int w(java.lang.String,java.lang.String)>";
                break;
            case "e":
                methodName = isContainException ? "<android.util.Log: int e(java.lang.String,java.lang.String,java.lang.Throwable)>"
                        : "<android.util.Log: int e(java.lang.String,java.lang.String)>";
                break;
            case "wtf":
                methodName = isContainException ? "<android.util.Log: int wtf(java.lang.String,java.lang.String,java.lang.Throwable)>"
                        : "<android.util.Log: int wtf(java.lang.String,java.lang.String)>";
                break;
            default:
                throw new IllegalArgumentException("Unknown log level: " + level);
        }

        return methodName;
    }
}