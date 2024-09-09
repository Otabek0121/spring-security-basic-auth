package uz.pdp.springsecuritybasicauth.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/hello")
public class HelloController {


    @GetMapping("open")
    public String open(){
        return "Hello bro this open page";
    }


    @GetMapping("close")
    public String close(){

        return "Hello bro this close page";
    }


}
