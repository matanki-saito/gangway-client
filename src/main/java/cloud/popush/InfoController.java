package cloud.popush;

import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static cloud.popush.OAuthController.SESSION_COOKIE_NAME;

@RestController
@RequestMapping("info")
class InfoController {
    @GetMapping("")
    public Info getInfo(@CookieValue(name = SESSION_COOKIE_NAME, required = false) String session) {
        return new Info()
                .setApplication("tutorial-social-logins")
                .setSession(session);
    }

    @Data
    @Accessors(chain = true)
    private static class Info {
        private String application;
        private String session;
    }

}
