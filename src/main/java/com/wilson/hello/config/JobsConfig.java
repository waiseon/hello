package com.wilson.hello.config;

import com.wilson.hello.dto.IBECronJobConfig;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@ConfigurationProperties(prefix="cathay.cron-jobs-config")
public class JobsConfig {

    private List<IBECronJobConfig> jobList;

    public List<IBECronJobConfig> getJobList() {
        return jobList;
    }

    public void setJobList(List<IBECronJobConfig> jobList) {
        this.jobList = jobList;
    }
}
