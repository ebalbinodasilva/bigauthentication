package org.example;

import io.swagger.v3.oas.models.security.OAuthFlows;
import org.springdoc.core.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Your API Title")
                        .version("1.0.0")
                        .description("API description here."))
                .addSecurityItem(new SecurityRequirement().addList("oauth2_scheme"))
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("oauth2_scheme", new SecurityScheme()
                                .type(SecurityScheme.Type.OAUTH2)
                                .flows(new OAuthFlows())));
    }

    @Bean
    public GroupedOpenApi apiGroup() {
        return GroupedOpenApi.builder()
                .group("Default API Group")
                .pathsToMatch("/api/**")
                .build();
    }
}

