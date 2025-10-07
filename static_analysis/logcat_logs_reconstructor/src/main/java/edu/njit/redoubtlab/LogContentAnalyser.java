package edu.njit.redoubtlab;

import edu.njit.redoubtlab.common.Utils;
import edu.njit.redoubtlab.element.CallerCalleeParams;
import edu.njit.redoubtlab.element.CallerPaths;
import edu.njit.redoubtlab.element.ContentValue;
import edu.njit.redoubtlab.element.MethodParam;
import soot.*;
import soot.jimple.StringConstant;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JIdentityStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;

public class LogContentAnalyser {

    private CallGraph callGraph;

    private SootMethod endCalleeMethod;

    private Set<Integer> endCalleeParamIndexes;

    public static String VAR_PLACEHOLDER = "<VARIABLE_PLACEHOLDER>";

    public LogContentAnalyser(CallGraph callGraph,
                              SootMethod endCalleeMethod,
                              Set<Integer> calleeParamIndexes) {
        this.callGraph = callGraph;
        this.endCalleeMethod = endCalleeMethod;
        this.endCalleeParamIndexes = calleeParamIndexes;
    }

    public Map<Integer, List<String>> analyse() throws Exception {
        Map<Integer, List<String>> res = new HashMap<>();
        Map<SootMethod, Set<CallerCalleeParams>> result = analyseContent(endCalleeMethod, endCalleeParamIndexes, 0, new HashSet<>());
        for (SootMethod method : result.keySet()) {
            for (CallerCalleeParams params : result.get(method)) {
                for (MethodParam param : params.getCalleeParams()) {
                    res.computeIfAbsent(param.getIndex(), k -> new ArrayList<>()).add(param.getContent());
                }
            }
        }
        return res;
    }

    public Map<SootMethod, Set<CallerCalleeParams>> callerResultAnalyse() throws Exception {
        return analyseContent(endCalleeMethod, endCalleeParamIndexes, 0, new HashSet<>());
    }



    private Map<SootMethod, Set<CallerCalleeParams>> analyseContent(SootMethod calleeMethod,
                                                                    Set<Integer> calleeParamIndexes,
                                                                    int depth,
                                                                    Set<SootMethod> visitedMethods) throws Exception {


        if (depth > 5 || visitedMethods.contains(calleeMethod)) {
            return new HashMap<>();
        }


        visitedMethods.add(calleeMethod);
        Map<SootMethod, Set<CallerCalleeParams>> result = new HashMap<>();
        AtomicInteger edgeNumber = new AtomicInteger();

        Iterator<Edge> edgeIterator = callGraph.edgesInto(calleeMethod);
        while (edgeIterator.hasNext()) {
            SootMethod callerMethod = edgeIterator.next().getSrc().method();

            System.out.println(System.currentTimeMillis()+" Depth: " + depth + " Edge:" + edgeNumber + " Caller: " + callerMethod.getSignature() + " Callee: " + calleeMethod.getSignature());


            Set<CallerPaths> paths = Utils.getPaths(callerMethod, calleeMethod, calleeParamIndexes);
            Set<Integer> callerParamIndexes = new HashSet<>();
            Set<CallerCalleeParams> paramsSet = new HashSet<>();


            CallerCalleeParams emptyCallerParams = new CallerCalleeParams(callerMethod, calleeMethod, new HashSet<>());
            analyseContent(paths, callerMethod, calleeMethod, callerParamIndexes, paramsSet, emptyCallerParams);

            Map<SootMethod, Set<CallerCalleeParams>> backwardParams = new HashMap<>();


            if (!callerParamIndexes.isEmpty() && !paramsSet.isEmpty()) {
                backwardParams = analyseContent(callerMethod, callerParamIndexes, depth + 1, visitedMethods);
            }

            if (!backwardParams.isEmpty()) {
                paramsSet = new HashSet<>();
                for (SootMethod method : backwardParams.keySet()) {
                    for (CallerCalleeParams callerParam : backwardParams.get(method)) {
                        analyseContent(paths, callerMethod, calleeMethod, callerParamIndexes, paramsSet, callerParam);
                    }
                }
            }

            if (result.containsKey(callerMethod)) {
                result.get(callerMethod).addAll(paramsSet);
            } else {
                result.put(callerMethod, paramsSet);
            }
            System.out.println("Finish Depth: " + depth + " Edge:" + edgeNumber + " Caller: " + callerMethod.getSignature() + " Callee: " + calleeMethod.getSignature());
            edgeNumber.getAndIncrement();
        }

        return result;
    }


    private void analyseContent(Set<CallerPaths> paths,
                                SootMethod callerMethod,
                                SootMethod calleeMethod,
                                Set<Integer> callerParamIndexes,
                                Set<CallerCalleeParams> paramsSet,
                                CallerCalleeParams callerParam) throws Exception {
        for (CallerPaths path : paths) {
            Set<MethodParam> params = new HashSet<>();
            CallerCalleeParams calleeParams = new CallerCalleeParams(callerMethod, calleeMethod, params);
            Map<String, ContentValue> resMap = analyseLogContent(path.getUnits(), callerMethod, callerParam.calleeParamsToMap());
            for (Map.Entry<Integer, Value> entry : path.getArgValues().entrySet()) {
                if (entry.getValue() instanceof StringConstant) {
                    MethodParam calleeParam = new MethodParam();
                    calleeParam.setIndex(entry.getKey());
                    calleeParam.setContent(Utils.replaceDoubleQuotation(entry.getValue().toString()));
                    params.add(calleeParam);
                    continue;
                }
                ContentValue argValue = resMap.get(entry.getValue().toString());
                if (argValue != null && argValue.isAffectedByParam()) {
                    callerParamIndexes.addAll(argValue.getAffectingParam());
                }
                if (argValue != null) {
                    MethodParam calleeParam = new MethodParam();
                    calleeParam.setIndex(entry.getKey());
                    calleeParam.setContent(argValue.getContent());
                    params.add(calleeParam);
                }
            }
            if (!params.isEmpty()) {
                paramsSet.add(calleeParams);
            }
        }
    }

    private Map<String, ContentValue> analyseLogContent(List<Unit> units,
                                                        SootMethod callerMethod,
                                                        Map<Integer, String> paramContent) throws Exception {
        Map<String, ContentValue> varValueMap = new HashMap<>();

        for (Unit unit : units) {
            List<ValueBox> defBoxes = unit.getDefBoxes();
            Value defValue = defBoxes.size() == 1 ? defBoxes.get(0).getValue() : null;
            String defVarName = defBoxes.size() == 1 ? defBoxes.get(0).getValue().toString() : "N/A";

            if (!varValueMap.containsKey(defVarName) && !"N/A".equals(defVarName)) {
                ContentValue contentValue = new ContentValue(defValue, callerMethod.getSignature(), defVarName, "?");
                contentValue.setContent(VAR_PLACEHOLDER);
                varValueMap.put(defVarName, contentValue);
            }

            if (unit instanceof JIdentityStmt) {
                processIdentityStmt((JIdentityStmt) unit, defVarName, varValueMap, paramContent);
            } else if (unit instanceof JAssignStmt) {
                processAssignStmt((JAssignStmt) unit, defVarName, varValueMap);
            } else if (unit instanceof JInvokeStmt) {
                processInvokeStmt((JInvokeStmt) unit, defVarName, varValueMap);
            }
        }

        return varValueMap;
    }


    private void processIdentityStmt(JIdentityStmt stmt, String defVarName, Map<String, ContentValue> varValueMap, Map<Integer, String> paramContent) {
        ValueBox leftBox = stmt.getLeftOpBox();
        ValueBox rightBox = stmt.getRightOpBox();
        Type rightType = rightBox.getValue().getType();
        ContentValue contentValue = varValueMap.get(defVarName);
        if (rightBox.getValue().toString().startsWith("@parameter")) {
            contentValue.setIsAffectedByParam(true);
            Integer paramIndex = Utils.extractParamIndex(rightBox.getValue().toString());
            contentValue.getAffectingParam().add(paramIndex);
            contentValue.setContent(paramContent.getOrDefault(paramIndex, contentValue.getContent()));
        }else {
            if (rightType.toString().equals("java.lang.String") && !rightBox.getValue().toString().startsWith("@this")) {
                System.out.println(rightBox.getValue().toString());
                System.out.println(rightType);
                ContentValue rightContentValue = varValueMap.get(rightBox.getValue().toString());
                contentValue.setContent(rightContentValue.getContent());
                contentValue.setIsAffectedByParam(rightContentValue.isAffectedByParam());
                contentValue.setAffectingParam(new HashSet<>());
                contentValue.getAffectingParam().addAll(rightContentValue.getAffectingParam());
            }else {
                contentValue.setContent(VAR_PLACEHOLDER);
                contentValue.setIsAffectedByParam(false);
                contentValue.setAffectingParam(new HashSet<>());
            }
        }
    }

    private void processAssignStmt(JAssignStmt stmt, String defVarName, Map<String, ContentValue> varValueMap) throws Exception {
        ValueBox leftBox = stmt.getLeftOpBox();
        ValueBox rightBox = stmt.getRightOpBox();
        ContentValue contentValue = varValueMap.get(defVarName);
        if (rightBox.getValue().toString().contains("new java.lang.StringBuilder")) {
            contentValue.setContent("");
            contentValue.setIsAffectedByParam(false);
            contentValue.setAffectingParam(new HashSet<>());
            return;
        }

        if (rightBox.getValue().toString().startsWith("virtualinvoke")) {
            if (rightBox.getValue().toString().contains("java.lang.StringBuilder: java.lang.StringBuilder append")) {
                handleStrAppend(stmt, varValueMap, contentValue);

            } else if (rightBox.getValue().toString().contains("<java.lang.StringBuilder: java.lang.String toString()>()")
                    || rightBox.getValue().toString().contains("java.lang.String toString()>()")) {
                String varCalleeName = stmt.getRightOp().getUseBoxes().get(0).getValue().toString();
                ContentValue valueCallee = varValueMap.get(varCalleeName);

                contentValue.setContent(valueCallee.getContent());
                contentValue.setIsAffectedByParam(valueCallee.isAffectedByParam());
                contentValue.getAffectingParam().addAll(valueCallee.getAffectingParam());
            }else {
                contentValue.setContent(VAR_PLACEHOLDER);
                contentValue.setIsAffectedByParam(false);
                contentValue.setAffectingParam(new HashSet<>());
            }
        } else if (rightBox.getValue().toString().startsWith("staticinvoke")) {

            String rightBoxStr = rightBox.getValue().toString();
            if (rightBoxStr.contains("java.lang.String: java.lang.String format(java.lang.String,java.lang.Object[])")
            || rightBoxStr.contains("java.lang.String: java.lang.String format(java.util.Locale,java.lang.String,java.lang.Object[])")
            ) {
                Value formatArg=null;
                Value argsArg=null;
                List<ValueBox> boxes = stmt.getUseBoxes();
                ContentValue leftValue = varValueMap.get(leftBox.getValue().toString());
                if (rightBoxStr.contains("(java.lang.String,java.lang.Object[])")) {
                    formatArg = boxes.get(1).getValue();
                    argsArg = boxes.get(2).getValue();
                } else if (rightBoxStr.contains("java.util.Locale,java.lang.String,java.lang.Object[]")) {
                    formatArg = boxes.get(2).getValue();
                    argsArg = boxes.get(3).getValue();
                }
                if (formatArg==null || argsArg == null) {
                   return;
                }

                if (formatArg instanceof StringConstant) {
                    String content = Utils.replaceDoubleQuotation(formatArg.toString());
                    content = Utils.replacePlaceholders(content, argsArg.toString(), varValueMap);
                    leftValue.setContent(content);
                } else {
                    ContentValue valueFormatArg = varValueMap.get(formatArg.toString());
                    leftValue.setContent(valueFormatArg.getContent());
                    leftValue.setIsAffectedByParam(valueFormatArg.isAffectedByParam());
                    leftValue.getAffectingParam().addAll(valueFormatArg.getAffectingParam());
                }
            }else {
                contentValue.setContent(VAR_PLACEHOLDER);
                contentValue.setIsAffectedByParam(false);
                contentValue.setAffectingParam(new HashSet<>());
            }
        }else {
            contentValue.setContent(VAR_PLACEHOLDER);
            contentValue.setIsAffectedByParam(false);
            contentValue.setAffectingParam(new HashSet<>());
        }
    }

    private void handleStrAppend(JAssignStmt stmt, Map<String, ContentValue> varValueMap, ContentValue contentValue) throws Exception {
        String varCalleeName = stmt.getRightOp().getUseBoxes().get(0).getValue().toString();
        String argCallee = stmt.getRightOp().getUseBoxes().get(1).getValue().toString();
        String content = getStringBuilderContent(varCalleeName, argCallee, varValueMap);

        ContentValue valueCallee = varValueMap.get(varCalleeName);
        Boolean isAffectedByParam = false;
        if (varValueMap.containsKey(argCallee)) {
            isAffectedByParam = varValueMap.get(argCallee).isAffectedByParam();
            contentValue.getAffectingParam().addAll(varValueMap.get(argCallee).getAffectingParam());
        }
        contentValue.setContent(content);
        contentValue.setIsAffectedByParam(valueCallee.isAffectedByParam() || isAffectedByParam);
        contentValue.getAffectingParam().addAll(valueCallee.getAffectingParam());
    }


    private String getStringBuilderContent(String varCalleeName, String argCallee, Map<String, ContentValue> varValueMap) throws Exception {

        argCallee = Utils.replaceDoubleQuotation(argCallee);

        ContentValue calleeValue = varValueMap.get(varCalleeName);
        ContentValue argValue = varValueMap.get(argCallee);

        if (varValueMap.containsKey(varCalleeName) && varValueMap.containsKey(argCallee)) {
            if ((calleeValue.getContent().length() + argValue.getContent().length())>=1000000) {
                throw new Exception("String length is too long");
            }
            return calleeValue.getContent() + argValue.getContent();
        }
        if ((calleeValue.getContent().length() + argCallee.length())>=1000000) {
            throw new Exception("String length is too long");
        }
        return calleeValue.getContent() + argCallee;
    }

    private void processInvokeStmt(JInvokeStmt stmt, String defVarName, Map<String, ContentValue> varValueMap) throws Exception {
        if (stmt.getInvokeExprBox().getValue().toString().contains("<java.lang.StringBuilder: void <init>()>()")) {
            if ("N/A".equals(defVarName)) {
                return;
            }
            ContentValue valueCallee = varValueMap.get(defVarName);
            valueCallee.setContent("");
            valueCallee.setIsAffectedByParam(false);
            valueCallee.setAffectingParam(new HashSet<>());
        } else if (stmt.getInvokeExprBox().getValue().toString().contains("<java.lang.StringBuilder: void <init>(java.lang.String)>")) {
            String varCalleeName = stmt.getUseBoxes().get(0).getValue().toString();
            if (stmt.getUseBoxes().get(1).getValue() instanceof StringConstant) {
                String argCallee = stmt.getUseBoxes().get(1).getValue().toString();
                ContentValue valueCallee = varValueMap.get(varCalleeName);
                valueCallee.setContent(Utils.replaceDoubleQuotation(argCallee));
                valueCallee.setIsAffectedByParam(false);
                valueCallee.setAffectingParam(new HashSet<>());
            }else {
                ContentValue valueCallee = varValueMap.get(varCalleeName);
                String argCallee = stmt.getUseBoxes().get(1).getValue().toString();
                ContentValue valueArg = varValueMap.get(argCallee);
                valueCallee.setContent(valueArg.getContent());
                valueCallee.setIsAffectedByParam(valueArg.isAffectedByParam());
                valueCallee.getAffectingParam().addAll(valueArg.getAffectingParam());
            }
        }
        else if (stmt.getInvokeExprBox().getValue().toString().contains("java.lang.StringBuilder: java.lang.StringBuilder append")) {
            String varCalleeName = stmt.getUseBoxes().get(0).getValue().toString();
            String argCallee = stmt.getUseBoxes().get(1).getValue().toString();
            String content = getStringBuilderContent(varCalleeName, argCallee, varValueMap);
            ContentValue valueCallee = varValueMap.get(varCalleeName);

            Boolean isAffectedByParam = false;
            if (varValueMap.containsKey(argCallee)) {
                isAffectedByParam = varValueMap.get(argCallee).isAffectedByParam();
                valueCallee.getAffectingParam().addAll(varValueMap.get(argCallee).getAffectingParam());
            }
            valueCallee.setContent(content);
            valueCallee.setIsAffectedByParam(valueCallee.isAffectedByParam() || isAffectedByParam);
            valueCallee.getAffectingParam().addAll(valueCallee.getAffectingParam());
        }
    }
}
