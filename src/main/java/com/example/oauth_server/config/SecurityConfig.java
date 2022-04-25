package com.example.oauth_server.config;

import com.example.oauth_server.security.oauth2.*;
import com.example.oauth_server.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CustomUserDetailsService customUserDetailsService;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;
    private final AuthorizationRequestRepository authorizationRequestRepository;

    private final TokenAuthenticationFilter tokenAuthenticationFilter;

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/h2-console/**");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(customUserDetailsService)
                .passwordEncoder(passwordEncoder());
    }


    @Override
    protected void configure(HttpSecurity security) throws Exception {
        security
                .csrf(config -> config.disable())
                .headers(config -> {
                    config.frameOptions().disable();
                })
                // Endpoint protection
                .authorizeHttpRequests(config -> {
                    config.antMatchers("/oauth/**", "/oauth2/**", "/h2-console/**").permitAll();
                    config.antMatchers("/join", "/revoke_token").permitAll();
                    config.anyRequest().authenticated();
                })
                .formLogin(config -> config.and())
                .httpBasic(config -> config.and())
                // Disable "JSESSIONID" cookies
                .sessionManagement(config -> {
                    config.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                })
                // OAuth2 (social logins)
                .oauth2Login(config -> {
                    config.authorizationEndpoint(subconfig -> {
                        subconfig.baseUri(OAuthConstant.AUTHORIZATION_BASE_URL);
                        subconfig.authorizationRequestRepository(authorizationRequestRepository);
                    });
//                    config.redirectionEndpoint(subconfig -> {
//                        subconfig.baseUri(OAuthConstant.CALLBACK_BASE_URL + "/*");
//                    });
//                    config.userInfoEndpoint(subconfig -> {
//                        subconfig.userService(customOAuth2UserService);
//                    });
//                    config.authorizedClientService(customAuthorizedClientService);
                    config.successHandler(oAuth2AuthenticationSuccessHandler);
                    config.failureHandler(oAuth2AuthenticationFailureHandler);
                })
                // Filters
                .addFilterBefore(tokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // Auth exceptions
                .exceptionHandling(config -> {
                    config.accessDeniedHandler(this::accessDenied);
//                    config.authenticationEntryPoint(this::accessDenied);
                });
    }

    private void accessDenied(HttpServletRequest request, HttpServletResponse response, Exception authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{ \"error\": \"Access Denied\" }");
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

//    @Bean
//    public AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository() {
//        return new HttpSessionOAuth2AuthorizationRequestRepository();
//    }


//    @Bean
//    public PasswordEncoder passwordEncoder() {
////        return new BCryptPasswordEncoder();
//        return NoOpPasswordEncoder.getInstance();
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
