package com.wilson.hello.dto;


public class IBECronJobConfig implements ICronJobConfig {

    private static final long serialVersionUID = 5136744807892747731L;

    private String jobId;
    private String springJobId;
    private String cronExpression;
    private String params;
    private String groupId = "DEFAULT";
    private String inCondition;
    private String outCondition;
    private String reqestCondition;
    private String startOnHold = "";


    @Override
    public String getStartOnHold() {
        return startOnHold;
    }


    public void setStartOnHold(String startOnHold) {
        this.startOnHold = startOnHold;
    }


    @Override
    public String getReqestCondition() {
        return reqestCondition;
    }


    public void setReqestCondition(String reqestCondition) {
        this.reqestCondition = reqestCondition;
    }

    @Override
    public String getJobId() {
        return jobId;
    }

    public void setJobId(String jobId) {
        this.jobId = jobId;
    }

    @Override
    public String getCronExpression() {
        return cronExpression;
    }

    public void setCronExpression(String cronExpression) {
        this.cronExpression = cronExpression;
    }


    @Override
    public String getParams() {
        return params;
    }

    public void setParams(String params) {
        this.params = params;
    }

    @Override
    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }


    @Override
    public String getSpringJobId() {
        return springJobId;
    }

    public void setSpringJobId(String springJobId) {
        this.springJobId = springJobId;
    }

    public String getInCondition() {
        return inCondition;
    }

    public void setInCondition(String inCondition) {
        this.inCondition = inCondition;
    }

    public String getOutCondition() {
        return outCondition;
    }

    public void setOutCondition(String outCondition) {
        this.outCondition = outCondition;
    }
}