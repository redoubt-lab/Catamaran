package edu.njit.redoubtlab.common;

import edu.njit.redoubtlab.element.CallerPaths;
import edu.njit.redoubtlab.element.ContentValue;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.Stmt;
import soot.toolkits.graph.ExceptionalUnitGraph;

import java.io.File;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static edu.njit.redoubtlab.LogContentAnalyser.VAR_PLACEHOLDER;

public class Utils {
    public static boolean isSystemMethod(SootMethod method) {
        String className = method.getDeclaringClass().getName();
        return className.startsWith("android.") ||
                className.startsWith("com.android.") ||
                className.startsWith("com.google.");
    }

    public static String replacePlaceholders(String format, String replacement, Map<String, ContentValue> varValueMap) {
        try {
            String regex = "%[\\d$]*[-#+ 0,(]*\\d*(\\.\\d+)?[a-zA-Z]";
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(format);

            StringBuffer result = new StringBuffer();
            int index = 0;

            while (matcher.find()) {
                String key = replacement + '[' + index + ']';
                String replacementValue = varValueMap.get(key) != null ? varValueMap.get(key).getContent() : VAR_PLACEHOLDER;

                replacementValue = Matcher.quoteReplacement(replacementValue);
                matcher.appendReplacement(result, replacementValue);
                index++;
            }
            matcher.appendTail(result);

            return result.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return format;
    }
    public static String replaceDoubleQuotation(String input) {
        if (input.startsWith("\"") && input.endsWith("\"")) {
            input = input.substring(1, input.length() - 1);
        }
        return input;
    }


    public static String findApk(String apkName, String folderPath) {
        File folder = new File(folderPath);
        List<String> apkPaths = new ArrayList<>();
        searchApkFiles(folder, apkName, apkPaths);

        if (!apkPaths.isEmpty()) {
            return apkPaths.get(0);
        } else {
            return "";
        }
    }


    private static void searchApkFiles(File folder, String apkName, List<String> apkPaths) {
        if (folder.isDirectory()) {
            File[] files = folder.listFiles();
            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        searchApkFiles(file, apkName, apkPaths);
                    } else if (file.isFile() && file.getName().equals(apkName)) {
                        apkPaths.add(file.getAbsolutePath());
                    }
                }
            }
        }
    }


    public static Integer extractParamIndex(String input) {
        String regex = "\\d+";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(input);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group());
        }
        return null;
    }

    public static Set<List<Unit>> getUnitPathsWithinMethod(ExceptionalUnitGraph graph) {
        Set<List<Unit>> uniquePaths = new HashSet<>();
        List<Unit> headUnits = graph.getHeads();
        long limit = 1000;
        long startTime = System.currentTimeMillis();
        long timeLimitSeconds = 300;

        for (Unit headUnit : headUnits) {
            Set<Unit> visited = new HashSet<>();
            List<Unit> currentPath = new ArrayList<>();
            findPathsDFS(graph, headUnit, currentPath, uniquePaths, visited, limit, startTime, timeLimitSeconds);
        }

        return uniquePaths;
    }

    private static void findPathsDFS(ExceptionalUnitGraph graph,
                                     Unit currentUnit,
                                     List<Unit> currentPath,
                                     Set<List<Unit>> uniquePaths,
                                     Set<Unit> visited,
                                     long limit,
                                     long startTime,
                                     long timeLimitSeconds) {

        currentPath.add(currentUnit);
        visited.add(currentUnit);

        List<Unit> successors = graph.getSuccsOf(currentUnit);
        if (successors.isEmpty()) {
            uniquePaths.add(new ArrayList<>(currentPath));
        } else {
            for (Unit successor : successors) {
                if (uniquePaths.size() >= limit) {
                    break;
                }
                long currentTime = System.currentTimeMillis();
                if (currentTime - startTime >= timeLimitSeconds * 1000) {
                    uniquePaths.add(currentPath);
                    return;
                }

                if (!visited.contains(successor)) {
                    findPathsDFS(graph, successor, currentPath, uniquePaths, visited, limit, startTime, timeLimitSeconds);
                }
            }
        }

        currentPath.remove(currentPath.size() - 1);
        visited.remove(currentUnit);
    }

    public static Set<CallerPaths> getPaths(SootMethod caller,
                                            SootMethod callee,
                                            Set<Integer> calleeParamIndexes) {
        ExceptionalUnitGraph unitGraph = new ExceptionalUnitGraph(caller.retrieveActiveBody());
        Set<List<Unit>> unitPaths = Utils.getUnitPathsWithinMethod(unitGraph);
        Set<CallerPaths> paths = new HashSet<>();

        for (List<Unit> units : unitPaths) {
            List<Unit> callerUnits = new ArrayList<>();
            Map<Integer, Value> calleeArgs = new HashMap<>();

            for (Unit unit : units) {
                callerUnits.add(unit);
                if (unit instanceof Stmt stmt && stmt.containsInvokeExpr() &&
                        stmt.getInvokeExpr().getMethod().getSignature().equals(callee.getSignature())) {
                    List<Value> args = stmt.getInvokeExpr().getArgs();
                    for (int index : calleeParamIndexes) {
                        if (args.size() > index) {
                            calleeArgs.put(index, args.get(index));
                        }
                    }
                    CallerPaths path = new CallerPaths(new ArrayList<>(callerUnits), calleeArgs, callee);
                    paths.add(path);
                }
            }
        }
        return paths;
    }



    public String getVarShortName(String fullVariableName) {
        int endIndex = fullVariableName.indexOf('>');

        if (endIndex != -1 && endIndex < fullVariableName.length() - 1) {
            return fullVariableName.substring(endIndex + 2);
        } else {
            return "";
        }
    }


    public static String extractPackageName(String fileName) {
        if (fileName.endsWith(".apk")) {
            fileName = fileName.substring(0, fileName.length() - 4);
        }
        String[] parts = fileName.split("\\.");
        if (parts.length < 2) {
            return fileName;
        }
        return parts[0] + "." + parts[1];
    }

    public static List<String> getApkFilesFromFolder(File folder) {
        List<String> apkFiles = new ArrayList<>();
        if (folder.exists() && folder.isDirectory()) {
            File[] files = folder.listFiles();

            if (files != null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        apkFiles.addAll(getApkFilesFromFolder(file));
                    } else if (file.isFile() && file.getName().toLowerCase().endsWith(".apk")) {
                        apkFiles.add(file.getAbsolutePath());
                    }
                }
            }
        }
        return apkFiles;
    }


}
