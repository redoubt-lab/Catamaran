package edu.njit.redoubtlab.result;

public class TestResult {
    private String apkName;
    private String graphMemMB;
    private String findingOutputsTime;
    private boolean isSuccess;

    public TestResult() {
    }

    public TestResult(String apkName,
                      String graphMemMB,
                      String findingOutputsTime,
                      boolean isSuccess) {
        this.apkName = apkName;
        this.graphMemMB = graphMemMB;
        this.findingOutputsTime = findingOutputsTime;
        this.isSuccess = isSuccess;
    }

    public String getApkName() {
        return apkName;
    }

    public void setApkName(String apkName) {
        this.apkName = apkName;
    }

    public String getFindingOutputsTime() {
        return findingOutputsTime;
    }

    public void setFindingOutputsTime(String findingOutputsTime) {
        this.findingOutputsTime = findingOutputsTime;
    }

    public boolean isSuccess() {
        return isSuccess;
    }

    public void setSuccess(boolean success) {
        isSuccess = success;
    }

    public String getGraphMemMB() {
        return graphMemMB;
    }

    public void setGraphMemMB(String graphMemMB) {
        this.graphMemMB = graphMemMB;
    }
}