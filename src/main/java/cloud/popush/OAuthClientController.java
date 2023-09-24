package cloud.popush;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;


@RequiredArgsConstructor
@RestController
@Slf4j
public class OAuthClientController {
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final JwtDecoder jwtDecoder;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;

    @GetMapping("/ido-front")
    public String front(Authentication authentication,
                        HttpServletResponse response,
                        @RequestParam(value = "url") String url) throws Exception {

        OAuth2AuthorizedClient authorizedClient = authorizedClientService.loadAuthorizedClient(
                "keycloak",
                authentication.getName()
        );

        if (authorizedClient == null) {
            return "error";
        }

        var token = authorizedClient.getAccessToken().getTokenValue();

        var jwt = jwtDecoder.decode(token);
        var result = jwtAuthenticationConverter.convert(jwt);

        if (result.isAuthenticated()) {
            log.info("scope:{}", result.getAuthorities());
        }

        Cookie cookie = new Cookie("far-caress", token);
        cookie.setMaxAge(265 * 24 * 60 * 60);
        cookie.setPath("/");
        response.addCookie(cookie);

        response.sendRedirect(url);

        return "abc";
    }
}
