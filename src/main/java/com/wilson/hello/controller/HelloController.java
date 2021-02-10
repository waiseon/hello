package com.wilson.hello.controller;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.wilson.hello.dto.DecryptedRequestDTO;
import com.wilson.hello.dto.Person;
import com.wilson.hello.utils.EncryptionUtil;
import org.apache.tomcat.util.buf.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.regex.Pattern;

@RestController
public class HelloController {

    @Autowired
    private Person person;

    @Autowired
    private EncryptionUtil encryptionUtil;

    @RequestMapping(value = "/hello", method = RequestMethod.GET)
    public String test(HttpServletRequest request) {
//        String reg = "^[0-9]{0,20}(\\.[0-9]{0,9}){0,1}$";
        String reg = "^[0-9]{1,2}-[a-zA-Z]{3}-[0-9]{2}$";
        String input = request.getParameter("input");
        String format = "dd-MMM-yy";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(format);
        if (Pattern.matches(reg, input)){
            try {
                simpleDateFormat.setLenient(false);
                System.out.println(simpleDateFormat.parse(input));
                return simpleDateFormat.parse(input).toString();
            } catch (ParseException e) {
                return "wrong date format";
            }
        }
//        String reg = request.getParameter("reg");
//        Person person = new Person();
//        person.setName("Wilson");
//        person.setAge(18);
//        Person.Job job = new Person.Job();
//        job.setTitle("SSE");
//        person.setJob(job);
        return "not match pattern";
    }

    @RequestMapping(value = "/test/regex", method = RequestMethod.GET)
    public boolean testRegex(@RequestHeader(name = "regex") String regexHeader, @RequestHeader(name = "to_validate") String toValidateHeader,
            @RequestParam(name = "regex", required = false) String regex, @RequestParam(name = "to_validate", required = false) String toValidate){
        if (Pattern.matches(regexHeader, toValidateHeader)){
            return true;
        }
        return false;
    }

    @GetMapping(value = "/encrypt")
    public ResponseEntity<String> encryption(@RequestBody JsonNode jsonObject) throws Exception {
        String encryptedData = encryptionUtil.encrypt(jsonObject);
//        JsonNode decryptedData = encryptionUtil.decrypt(encryptedData, new TypeReference<JsonNode>() {
//        });

        return new ResponseEntity<>(encryptedData,
                HttpStatus.OK);
    }

    @GetMapping(value = "/decrypt")
    public ResponseEntity<JsonNode> decryption(@RequestBody DecryptedRequestDTO request) throws Exception {
        String encryptedData = request.getEncryptedData();
        JsonNode decryptedData = encryptionUtil.decrypt(encryptedData, new TypeReference<JsonNode>() {
        });

        return new ResponseEntity<>(decryptedData,
                HttpStatus.OK);
    }
}
