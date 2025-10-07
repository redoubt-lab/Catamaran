package edu.njit.redoubtlab.element;

import soot.Value;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ContentValue {
    Value sootValue;
    String methodSignature;
    String valueName;
    String content;
    Boolean isAffectedByParam = false;
    Set<Integer> affectingParam =new HashSet<>();


    public ContentValue(Value sootValue,
                        String methodSignature,
                        String valueName,
                        String content) {
        this.sootValue = sootValue;
        this.methodSignature = methodSignature;
        this.valueName = valueName;
        this.content = content;
    }

    public Value getSootValue() {
        return sootValue;
    }

    public void setSootValue(Value sootValue) {
        this.sootValue = sootValue;
    }

    public String getMethodSignature() {
        return methodSignature;
    }

    public void setMethodSignature(String methodSignature) {
        this.methodSignature = methodSignature;
    }

    public String getValueName() {
        return valueName;
    }

    public void setValueName(String valueName) {
        this.valueName = valueName;
    }

    public void setAffectingParam(Set<Integer> affectingParam) {
        this.affectingParam = affectingParam;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    @Override
    public String toString() {
        return methodSignature+"."+valueName;
    }

    @Override
    public int hashCode() {
        return Objects.hash(methodSignature, valueName);
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ContentValue that = (ContentValue) o;
        return Objects.equals(methodSignature, that.methodSignature) &&
                Objects.equals(valueName, that.valueName);
    }

    public Boolean isAffectedByParam() {
        return isAffectedByParam;
    }

    public void setIsAffectedByParam(Boolean affectedByParam) {
        isAffectedByParam = affectedByParam;
    }

    public Set<Integer> getAffectingParam() {
        return affectingParam;
    }

}
