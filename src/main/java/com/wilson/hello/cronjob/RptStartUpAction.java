package com.wilson.hello.cronjob;

import com.wilson.hello.config.JobsConfig;
import com.wilson.hello.dto.ICronJobConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class RptStartUpAction implements ApplicationListener<ContextRefreshedEvent> {

    @Autowired
    private JobsConfig jobsConfig;

    @Override
    public void onApplicationEvent(ContextRefreshedEvent contextRefreshedEvent) {
        List<? extends ICronJobConfig> jobList = jobsConfig.getJobList();

        if (null != jobList && jobList.size() > 0) {
            Map<String, Long> collect = jobList.stream().collect(Collectors.groupingBy(ICronJobConfig::getJobId , Collectors.counting()));
            collect.forEach((k, v) -> {
                if (v > 1) {
                    System.exit(-1);
                }
            });
        } else {
            return;
        }
    }
}
