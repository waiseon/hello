package com.wilson.hello.controller;

import com.wilson.hello.dto.Person;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.regex.Pattern;

@RestController
public class HelloController {

    @Autowired
    private Person person;

    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public boolean test(HttpServletRequest request){
        String reg="^[0-9]{0,20}(\\.[0-9]{0,9}){0,1}$";
        String input = request.getParameter("input");
//        String reg = request.getParameter("reg");
//        Person person = new Person();
//        person.setName("Wilson");
//        person.setAge(18);
//        Person.Job job = new Person.Job();
//        job.setTitle("SSE");
//        person.setJob(job);
        return Pattern.matches(reg, input);
    }
}
