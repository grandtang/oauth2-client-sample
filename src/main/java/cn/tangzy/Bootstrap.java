package cn.tangzy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

/**
 * Hello world!
 */
@SpringBootApplication
@Controller
public class Bootstrap {

    public static void main(String[] args) {
        SpringApplication.run(Bootstrap.class, args);
    }

    @RequestMapping("/hello")
    @ResponseBody
    public Object hello() {
        return   SecurityContextHolder.getContext().getAuthentication();
//    return "8181";
    }

    @RequestMapping({"/redirect/", "/redirect"})
    @ResponseBody
    public Object redirect() {
      return   SecurityContextHolder.getContext().getAuthentication();
    }

    //    @Autowired
    OAuth2RestTemplate oAuth2RestTemplate;
}
