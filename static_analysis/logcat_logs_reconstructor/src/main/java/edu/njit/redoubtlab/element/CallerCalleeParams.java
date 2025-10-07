package edu.njit.redoubtlab.element;

import soot.SootMethod;

import java.util.*;

public class CallerCalleeParams {
    SootMethod caller;
    SootMethod callee;
    Set<MethodParam> calleeParams =new HashSet<>();

    public CallerCalleeParams(SootMethod caller, SootMethod callee, Set<MethodParam> calleeParams) {
        this.caller = caller;
        this.callee = callee;
        this.calleeParams = calleeParams;
    }

    public SootMethod getCaller() {
        return caller;
    }

    public void setCaller(SootMethod caller) {
        this.caller = caller;

    }

    public SootMethod getCallee() {
        return callee;
    }

    public void setCallee(SootMethod callee) {
        this.callee = callee;
    }

    public Set<MethodParam> getCalleeParams() {
        return calleeParams;
    }

    public void setCalleeParams(Set<MethodParam> calleeParams) {
        this.calleeParams = calleeParams;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        CallerCalleeParams that = (CallerCalleeParams) obj;
        return this.hashCode() == that.hashCode();
    }

    @Override
    public int hashCode() {
        StringBuilder builder = new StringBuilder();
        for (MethodParam param : calleeParams) {
            builder.append(param.hashCode());
        }
        return Objects.hash(caller.getSignature(), callee.getSignature(), builder.toString());
    }
    public Map<Integer,String> calleeParamsToMap(){
        Map<Integer,String> map = new HashMap<>();
        for(MethodParam param : calleeParams){
            map.put(param.getIndex(),param.getContent());
        }
        return map;
    }
}
