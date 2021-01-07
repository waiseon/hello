package com.wilson.hello.scheduler;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class TestScheduler {

    @Scheduled(cron = "0/5 * *  * * ?")
    public void testScheduler(){
        System.out.println(new Date());
    }
}
