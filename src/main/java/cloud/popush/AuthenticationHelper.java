package cloud.popush;

import lombok.Data;
import lombok.experimental.Accessors;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

public class AuthenticationHelper {
    public static void attachAccessToken(Authentication authentication, String token) {
        Object originalDetails = authentication.getDetails();
        if (originalDetails instanceof Details details) {
            details.setAccessToken(token);
        } else {
            Details details = new Details()
                    .setOriginal(originalDetails)
                    .setAccessToken(token);
            ((OAuth2AuthenticationToken) authentication).setDetails(details);
        }
    }

    public static String retrieveAccessToken(Authentication authentication) {
        Details details = (Details) authentication.getDetails();
        return details.getAccessToken();
    }

    @Data
    @Accessors(chain = true)
    private static class Details {

        private Object original;
        private String accountId;
        private String accessToken;

    }
}
