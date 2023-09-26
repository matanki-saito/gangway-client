package cloud.popush;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;


@Slf4j
@RestController
@AllArgsConstructor
public class OAuthController {

    /**
     * Default = {@value OAuth2AuthorizationRequestRedirectFilter#DEFAULT_AUTHORIZATION_REQUEST_BASE_URI}
     * <p>
     * For instance:
     * - /oauth2/authorization/auth0
     * - /oauth2/authorization/facebook
     * - /oauth2/authorization/google
     */
    public static final String AUTHORIZATION_BASE_URL = "/oauth2/authorization";

    /**
     * Default = {@value OAuth2LoginAuthenticationFilter#DEFAULT_FILTER_PROCESSES_URI}
     * <p>
     * For instance:
     * - /oauth2/callback/auth0
     * - /oauth2/callback/facebook
     * - /oauth2/callback/google
     */
    public static final String CALLBACK_BASE_URL = "/oauth2/callback";

    public static final String OAUTH_COOKIE_NAME = "OAUTH2";

    public static final String BEGIN_COOKIE_NAME = "begin";
    public static final String SESSION_COOKIE_NAME = "far-caress";

    private final CustomStatelessAuthorizationRequestRepository customStatelessAuthorizationRequestRepository;

    @GetMapping("/callback/{registrationId}")
    public String callback(@PathVariable String registrationId,
                           @RequestParam("state") String state,
                           @RequestParam("session_state") String session_state,
                           @RequestParam("code") String code,
                           HttpServletRequest request, HttpServletResponse response) throws Exception {

        response.sendRedirect("%s/%s?state=%s&session_state=%s&code=%s".formatted(
                CALLBACK_BASE_URL,
                registrationId,
                state,
                session_state,
                code
        ));

        return "";
    }

    @SneakyThrows
    public void oauthRedirectResponse(HttpServletRequest request, HttpServletResponse response, String url) {
        response.sendRedirect(url);
    }

    @SneakyThrows
    public void oauthSuccessCallback(OAuth2AuthorizedClient client, Authentication authentication) {
        AuthenticationHelper.attachAccessToken(authentication, client.getAccessToken().getTokenValue());
    }

    @SneakyThrows
    public void oauthSuccessResponse(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        String token = AuthenticationHelper.retrieveAccessToken(authentication);
        response.addHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME, request));
        response.addHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateCookie(SESSION_COOKIE_NAME, token, Duration.ofDays(1), request));

        var c = customStatelessAuthorizationRequestRepository.loadUrlFromAuthorization(request);
        if (c.isPresent()) {
            response.sendRedirect(c.get());
        }
    }

    @SneakyThrows
    public void oauthFailureResponse(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.SET_COOKIE, CookieHelper.generateExpiredCookie(OAUTH_COOKIE_NAME, request));
        response.getWriter().write("{ \"status\": \"failure\" }");
    }
}
