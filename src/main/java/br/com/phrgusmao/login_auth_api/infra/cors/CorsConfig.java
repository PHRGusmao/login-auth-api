package br.com.phrgusmao.login_auth_api.infra.cors;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class CorsConfig implements WebMvcConfigurer {

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**")
                .allowedOrigins("http://localhost:4200") // Origem do frontend
                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS") // Permitir mais métodos
                .allowedHeaders("Authorization", "Content-Type", "X-Requested-With") // Permitir cabeçalhos
                .exposedHeaders("Authorization") // Cabeçalhos que o frontend pode acessar
                .allowCredentials(true) // Permitir credenciais
                .maxAge(3600); // Tempo de cache do preflight
    }
}
