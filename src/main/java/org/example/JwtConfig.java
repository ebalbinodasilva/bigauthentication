package org.example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;



@Configuration
public class JwtConfig {

    @Bean
    public JwtDecoder jwtDecoder() {
        String jwkSetUri = "https://YOUR_TENANT.b2clogin.com/YOUR_TENANT/discovery/v2.0/keys?p=YOUR_USER_FLOW";

        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        OAuth2TokenValidator<Jwt> validator = JwtValidators.createDefaultWithIssuer("https://YOUR_TENANT.b2clogin.com/YOUR_TENANT/v2.0/");
        jwtDecoder.setJwtValidator(validator);

        return jwtDecoder;
    }
}
