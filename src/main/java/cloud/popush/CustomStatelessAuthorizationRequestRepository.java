package cloud.popush;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;

import static cloud.popush.OAuthController.BEGIN_COOKIE_NAME;

@Component
public class CustomStatelessAuthorizationRequestRepository implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {
    private static final Duration OAUTH_COOKIE_EXPIRY = Duration.ofMinutes(5);

    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final SecretKey encryptionKey;

    public CustomStatelessAuthorizationRequestRepository() {
        this.encryptionKey = EncryptionHelper.generateKey();
    }

    public CustomStatelessAuthorizationRequestRepository(@NonNull char[] encryptionPassword) {
        byte[] salt = {0}; // A static salt is OK for these short lived session cookies
        this.encryptionKey = EncryptionHelper.generateKey(encryptionPassword, salt);
    }

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        return this.retrieveCookie(request);
    }

    public Optional<String> loadUrlFromAuthorization(HttpServletRequest request) {
        return CookieHelper.retrieve(request.getCookies(), OAuthController.OAUTH_COOKIE_NAME)
                .map(this::decrypt)
                .map(Pack::getOriginUrl);
    }

    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request, HttpServletResponse response) {
        if (authorizationRequest == null) {
            this.removeCookie(response, request);
            return;
        }
        this.attachCookie(response, authorizationRequest, request);
    }

    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response) {
        return this.retrieveCookie(request);
    }

    private OAuth2AuthorizationRequest retrieveCookie(HttpServletRequest request) {
        return CookieHelper.retrieve(request.getCookies(), OAuthController.OAUTH_COOKIE_NAME)
                .map(this::decrypt)
                .map(Pack::getAuthorizationRequest)
                .orElse(null);
    }

    private void attachCookie(HttpServletResponse response, OAuth2AuthorizationRequest value, HttpServletRequest request) {
        var begin = request.getParameter(BEGIN_COOKIE_NAME);
        String cookie = CookieHelper.generateCookie(OAuthController.OAUTH_COOKIE_NAME, this.encrypt(new Pack(begin, value)), OAUTH_COOKIE_EXPIRY, request);
        response.setHeader(HttpHeaders.SET_COOKIE, cookie);
    }

    private void removeCookie(HttpServletResponse response, HttpServletRequest request) {
        String expiredCookie = CookieHelper.generateExpiredCookie(OAuthController.OAUTH_COOKIE_NAME, request);
        response.setHeader(HttpHeaders.SET_COOKIE, expiredCookie);
    }

    private String encrypt(Pack pack) {
        byte[] bytes = SerializationUtils.serialize(pack);
        byte[] encryptedBytes = EncryptionHelper.encrypt(this.encryptionKey, bytes);
        return B64E.encodeToString(encryptedBytes);
    }

    private Pack decrypt(String encrypted) {
        byte[] encryptedBytes = B64D.decode(encrypted);
        byte[] bytes = EncryptionHelper.decrypt(this.encryptionKey, encryptedBytes);
        return (Pack) SerializationUtils.deserialize(bytes);
    }

    @Data
    @Accessors(chain = true)
    @AllArgsConstructor
    private static class Pack implements Serializable {
        private String originUrl;
        private OAuth2AuthorizationRequest authorizationRequest;
    }

}
