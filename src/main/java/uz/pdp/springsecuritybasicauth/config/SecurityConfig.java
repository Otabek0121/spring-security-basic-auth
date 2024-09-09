package uz.pdp.springsecuritybasicauth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import uz.pdp.springsecuritybasicauth.security.AuthFilter;

@Configuration
@EnableWebSecurity

public class SecurityConfig {

    /**
     * BasicAuth da login qilinmaydi login qilish kerak emas
     */

    private final AuthFilter authFilter;

    public SecurityConfig(@Lazy AuthFilter authFilter) {
        this.authFilter = authFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(matcherRegistry -> {
            matcherRegistry.requestMatchers("/hello/open"
                    ).permitAll()
                    .anyRequest().authenticated();
        });

        /**
         *
         * Bu yerda httpSecuritySessionManagementConfigurer nima
         * uchun kerak?  men userlarni tekshirayotganda
         * authFilter ni ichida har safar yangi request kelganda uni
         * tekshirish uchun DB ga boeib kelmasligim kerak
         * Bu shuning oldini oladi. SessionCreationPolicy.ALWAYS  bunday yozilsa
         * u Session usulini qo'llaydi userni tanib olishi uchun
         *
         * Real projectda SessionCreationPolicy.STATELESS qilamiz.
         * bu holda token bilan ishlanadi
         *
         */

        http.addFilterBefore(authFilter, UsernamePasswordAuthenticationFilter.class);
        http.sessionManagement(httpSecuritySessionManagementConfigurer -> {
            httpSecuritySessionManagementConfigurer.sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
        });

        return http.build();

    }


    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user = User.builder()
                .username("user")
                .password("123")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("123")
                .build();
        return new InMemoryUserDetailsManager(user, admin);
    }


    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
