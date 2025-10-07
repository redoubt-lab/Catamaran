package edu.njit.redoubtlab;

import java.io.File;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import edu.njit.redoubtlab.common.Utils;
import edu.njit.redoubtlab.element.CallerCalleeParams;
import edu.njit.redoubtlab.element.LogcatMetaData;
import edu.njit.redoubtlab.element.MethodParam;
import edu.njit.redoubtlab.result.PossibleOutputDatabase;
import edu.njit.redoubtlab.result.ResultDatabase;
import edu.njit.redoubtlab.result.TestResult;
import jas.Pair;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.results.InfoflowResults;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinitionProvider;
import soot.jimple.toolkits.callgraph.CallGraph;

public class Main {


    private static final String APK_FOLDER_PATH = "";

    private static final String ANDROID_PLATFORM_DIR = "";

    private static final ResultDatabase resultDatabase = new ResultDatabase();

    private static Set<String> logLevels = new HashSet<>(List.of(new String[]{"d", "e", "i", "v", "w","wtf"}));

    private static final PossibleOutputDatabase possibleOutputDatabase = new PossibleOutputDatabase();

    public static void main(String[] args) {

        for (String apkPath:Utils.getApkFilesFromFolder(new File(APK_FOLDER_PATH))){
            String apkName = apkPath.substring(apkPath.lastIndexOf(File.separator) + 1);
            analyzeAPK(apkName, apkPath);
        }
    }

    private static void analyzeAPK(String apkName, String apkPath) {
        long graphMemMB=-1;
        long pathContentStartTime=0;
        long pathContentEndTime=0;
        boolean success = false;

        if (resultDatabase.existsApkName(apkName)) {
            return;
        }

        possibleOutputDatabase.deleteByApk(apkName);

        Scene.v().reset();
        InfoflowAndroidConfiguration config = createConfig(apkPath);
        SetupApplication app = new SetupApplication(config);

        System.out.println("Analyzing APK: " + apkPath);

        try {
            InfoflowResults results = constructCallgraph(app);
            graphMemMB = results.getPerformanceData().getMaxMemoryConsumption();
            CallGraph callGraph = Scene.v().getCallGraph();

            Set<SootMethod> logMethods = getLogMethods(logLevels);
            if (logMethods.isEmpty()) {
                System.out.println("No log methods found");
                return;
            }

            System.out.println("Analyzing log methods for finding log content for paths");
            pathContentStartTime = System.currentTimeMillis();
            Set<Pair<String,String>> pathsResult = analyzeLogMethods(callGraph, logMethods);
            for (Pair<String,String> pair : pathsResult) {
                possibleOutputDatabase.insert(apkName, pair.getO1(), pair.getO2());
            }
            pathContentEndTime = System.currentTimeMillis();
            System.out.println("Finishing Analyzing log methods for finding log content for paths");

            System.out.println("Analyzing logcat lines for matching variable");
            success = true;
        } catch (Exception e) {
            success = false;
        }
        TestResult result = new TestResult();
        result.setApkName(apkName);
        result.setFindingOutputsTime(String.valueOf(pathContentEndTime - pathContentStartTime));
        result.setGraphMemMB(String.valueOf(graphMemMB));
        result.setSuccess(success);
        resultDatabase.insertTestResult(result);
    }

    private static InfoflowAndroidConfiguration createConfig(String apkPath) {
        InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
        config.getAnalysisFileConfig().setTargetAPKFile(new File(apkPath));
        config.getAnalysisFileConfig().setAndroidPlatformDir(new File(ANDROID_PLATFORM_DIR));
        config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
        config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
        config.setMergeDexFiles(true);
        return config;
    }

    public static InfoflowResults constructCallgraph(SetupApplication app) throws NoSuchFieldException, IllegalAccessException {
        InfoflowAndroidConfiguration config = app.getConfig();
        InfoflowResults infoflowResults = new InfoflowResults();
        boolean oldRunAnalysis = config.isTaintAnalysisEnabled();
        try {
            config.setTaintAnalysisEnabled(false);
            if (!config.getSootIntegrationMode().needsToBuildCallgraph())
                throw new RuntimeException("FlowDroid is configured to use an existing callgraph. Please "
                        + "change this option before trying to create a new callgraph.");
            infoflowResults = app.runInfoflow((ISourceSinkDefinitionProvider) null);
            if (infoflowResults==null){
                throw new RuntimeException("failed to construct callgraph");
            }
        } catch (RuntimeException ex) {
            throw ex;
        } finally {
            config.setTaintAnalysisEnabled(oldRunAnalysis);
        }
        return infoflowResults;
    }

    private static Set<SootMethod> getLogMethods(Set<String> logLevels) {
        Set<SootMethod> logMethods = new HashSet<>();
        for (String logLevel : logLevels) {
            if (logLevel == null || logLevel.isEmpty()) {
                continue;
            }
            logMethods.add(Scene.v().getMethod(LogcatMetaData.getMethodName(logLevel, true)));
            logMethods.add(Scene.v().getMethod(LogcatMetaData.getMethodName(logLevel, false)));
        }
        return logMethods;
    }

    private static Set<Pair<String,String>> analyzeLogMethods(CallGraph callGraph, Set<SootMethod> logMethods) throws Exception {
        Set<Pair<String,String>> pathsResult = new HashSet<>();
        Set<Integer> calleeParamIndexes = Collections.singleton(1);
        for (SootMethod logMethod : logMethods) {
            LogContentAnalyser analyser = new LogContentAnalyser(callGraph, logMethod, calleeParamIndexes);
            Map<SootMethod, Set<CallerCalleeParams>> res = analyser.callerResultAnalyse();
            for (SootMethod method : res.keySet()) {
                for (CallerCalleeParams params : res.get(method)) {
                    for (MethodParam param : params.getCalleeParams()) {
                        if (param.getContent().isEmpty()) {
                            continue;
                        }
                        if (calleeParamIndexes.contains(param.getIndex())) {
                            Pair<String,String> pair = new Pair<>(method.getSignature(), param.getContent());
                            pathsResult.add(pair);
                        }
                    }
                }
            }
        }

        return pathsResult;
    }

}