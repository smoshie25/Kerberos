package org.example.krb;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @Author moshiem
 * created on 07/09/2022
 */
@Controller
public class MainController {

    @RequestMapping("/login")
    public String login() {
        return "login.html";
    }
}
