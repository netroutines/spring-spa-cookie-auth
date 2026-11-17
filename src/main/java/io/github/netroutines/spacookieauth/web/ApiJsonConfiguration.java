package io.github.netroutines.spacookieauth.web;

import org.springframework.boot.jackson.autoconfigure.JsonMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tools.jackson.databind.cfg.CoercionAction;
import tools.jackson.databind.cfg.CoercionInputShape;

@Configuration(proxyBeanMethods = false)
public class ApiJsonConfiguration {

    @Bean
    public JsonMapperBuilderCustomizer strictJsonStrings() {
        return builder -> builder.withCoercionConfig(String.class, coercion -> coercion
            .setCoercion(CoercionInputShape.Integer, CoercionAction.Fail)
            .setCoercion(CoercionInputShape.Float, CoercionAction.Fail)
            .setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail));
    }
}
