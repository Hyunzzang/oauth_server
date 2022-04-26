//package com.example.oauth_server.config;
//
//import lombok.RequiredArgsConstructor;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.http.HttpMethod;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
//import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
//import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
//import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
//import org.springframework.security.oauth2.provider.token.TokenStore;
//import org.springframework.security.web.util.matcher.RequestMatcher;
//
//import javax.servlet.http.HttpServletRequest;
//
//@Configuration
//@EnableResourceServer
//@EnableGlobalMethodSecurity(prePostEnabled=true)
//@RequiredArgsConstructor
//public class ResourceConfig extends ResourceServerConfigurerAdapter {
//
//    private final TokenStore tokenStore;
//    private final DefaultTokenServices tokenServices;
//
//    @Override
//    public void configure(ResourceServerSecurityConfigurer resources) {
//        resources
//                .resourceId(OAuthConstant.RESOURCE_ID)
//                .tokenServices(tokenServices)
//                .tokenStore(tokenStore);
//    }
//
//    @Override
//    public void configure(HttpSecurity http) throws Exception {
//        http
////                .requestMatcher(new OAuthRequestedMatcher())
//                .anonymous().disable()
//                .authorizeRequests()
//                .antMatchers("/oauth/**", "/oauth2/**", "/h2-console/**").permitAll()
//                .antMatchers("/join", "login", "/revoke_token").permitAll()
//                .antMatchers("/api/test/**").access("#oauth2.hasScope('read')")
//                .anyRequest().authenticated();
//    }
//
//    private static class OAuthRequestedMatcher implements RequestMatcher {
//        public boolean matches(HttpServletRequest request) {
//            String auth = request.getHeader("Authorization");
//            // Determine if the client request contained an OAuth Authorization
//            boolean haveOauth2Token = (auth != null) && auth.startsWith("Bearer");
//            boolean haveAccessToken = request.getParameter("access_token")!=null;
//            return haveOauth2Token || haveAccessToken;
//        }
//
//    }
//}
