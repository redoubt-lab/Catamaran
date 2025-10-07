package edu.njit.redoubtlab.element;

import soot.SootMethod;
import soot.Unit;
import soot.Value;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class CallerPaths {
    List<Unit> units;
    Map<Integer,Value> argValues =new HashMap<>();
    SootMethod calleeMethod;

    public CallerPaths(List<Unit> units, Map<Integer, Value> argValues, SootMethod calleeMethod) {
        this.units = units;
        this.argValues = argValues;
        this.calleeMethod = calleeMethod;
    }

    public List<Unit> getUnits() {
        return units;
    }

    public void setUnits(List<Unit> units) {
        this.units = units;
    }


    public SootMethod getCalleeMethod() {
        return calleeMethod;
    }

    public void setCalleeMethod(SootMethod calleeMethod) {
        this.calleeMethod = calleeMethod;
    }

    public Map<Integer, Value> getArgValues() {
        return argValues;
    }

    public void setArgValues(Map<Integer, Value> argValues) {
        this.argValues = argValues;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        CallerPaths that = (CallerPaths) obj;
        return this.hashCode() == that.hashCode();
    }

    @Override
    public int hashCode() {
        return Objects.hash(units, argValues, calleeMethod.getSignature());
    }
}
