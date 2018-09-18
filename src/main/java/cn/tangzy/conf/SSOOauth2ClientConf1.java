package cn.tangzy.conf;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.client.EnableOAuth2Sso;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenProviderChain;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * @author tangzhiyuan@bitnei.cn
 * @date 9/18/18
 **/
@Configuration
@EnableWebSecurity
@EnableOAuth2Sso
public class SSOOauth2ClientConf1 extends WebSecurityConfigurerAdapter {
//    @Autowired
//    OAuth2RestTemplate oauth2RestTemplate;
//    @Autowired
//    UserInfoTokenServices tokenService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/login").permitAll().anyRequest().authenticated()
                .and()
//                .addFilterBefore(
//                        oauth2ClientAuthenticationProcessingFilter(
//                                oauth2RestTemplate, tokenService
//                        ), BasicAuthenticationFilter.class
//                ).httpBasic().and()
                .csrf().disable();
    }

//    @Bean
//    public OAuth2RestTemplate oauth2RestTemplate(OAuth2ClientContext context, OAuth2ProtectedResourceDetails details) {
//        OAuth2RestTemplate template = new OAuth2RestTemplate(details, context);
//
//        AuthorizationCodeAccessTokenProvider authCodeProvider = new AuthorizationCodeAccessTokenProvider();
//        authCodeProvider.setStateMandatory(false);
//        AccessTokenProviderChain provider = new AccessTokenProviderChain(
//                Arrays.asList(authCodeProvider));
//        template.setAccessTokenProvider(provider);
//        return template;
//    }
//
//    @Bean
//    public OAuth2ClientAuthenticationProcessingFilter oauth2ClientAuthenticationProcessingFilter(
//            OAuth2RestTemplate oauth2RestTemplate,
//            ResourceServerTokenServices tokenService) {
//        OAuth2ClientAuthenticationProcessingFilter filter = new OAuth2ClientAuthenticationProcessingFilter("/redirect");
//        filter.setRestTemplate(oauth2RestTemplate);
//        filter.setTokenServices(tokenService);
//
//        //设置回调成功的页面
//        filter.setAuthenticationSuccessHandler(new SimpleUrlAuthenticationSuccessHandler() {
//            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                this.setDefaultTargetUrl(request.getRequestURI());
//                super.onAuthenticationSuccess(request, response, authentication);
//            }
//        });
//        return filter;
//    }

}
