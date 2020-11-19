package com.wilson.hello.dto;

import java.io.Serializable;

public interface ICronJobConfig extends Serializable {

    public abstract String getJobId();

    public abstract String getCronExpression();

    public abstract String getOutCondition();

    public abstract String getInCondition();

    public abstract String getReqestCondition();


    public abstract String getParams();

    public abstract String getGroupId();

    public abstract String getSpringJobId();

    public String getStartOnHold();



}