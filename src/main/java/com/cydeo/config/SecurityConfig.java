package com.cydeo.config;

import com.cydeo.service.SecurityService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration//I will create a bean
public class SecurityConfig {

        private final SecurityService securityService;
        private final AuthSuccessHandler authSuccessHandler;

        public SecurityConfig(SecurityService securityService, AuthSuccessHandler authSuccessHandler) {
            this.securityService = securityService;
            this.authSuccessHandler = authSuccessHandler;
        }

        //    @Bean
        // public UserDetailsService userDetailsService(PasswordEncoder encoder){//to create my own users
//
//        List<UserDetails>userList = new ArrayList<>();
//        userList.add(new User("mike",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_ADMIN"))));//CREATE NEW USER NEED TO PROVIDE CONSTRUCTOR
//        userList.add(new User("ozzy",encoder.encode("password"), Arrays.asList(new SimpleGrantedAuthority("ROLE_MANAGER"))));//CREATE NEW USER NEED TO PROVIDE CONSTRUCTOR
//        return new InMemoryUserDetailsManager(userList);//impl of UserDetailsService
//
//    }
        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

            return http
                    .authorizeRequests()
//               .antMatchers("/user/**").hasRole("ADMIN")//localhost/need to be access by Role Admin EVERYTHING FROM USER CONTROLLER SHOUD BE ACCESIBLE BY ADMIN
                    .antMatchers("/project/**").hasAuthority("Manager")
                    .antMatchers("/task/employee/**").hasAuthority("Employee")
                    .antMatchers("/task/**").hasAuthority("Manager")//ANYONE WITH ROLE ADMIN CAN ACCES HIS OWN PAGE
                    // .antMatchers("task/**").hasAnyRole("EMPLOYEE","ADMIN")
                    .antMatchers("/user/**").hasAuthority("Admin")//need to put role_admin,restrict the pages
                    .antMatchers(
                            "/login",
                            "/fragments/**",
                            "/assets/**",
                            "/images/**"
                    ).permitAll()//anyone can access the above andMatchers
                    .anyRequest().authenticated()
                    .and()
                    // .httpBasic()
                    .formLogin()//provide my own form to security
                    .loginPage("/login")
                    // .defaultSuccessUrl("/welcome")//after the user provide the correct username everybody needs to see welcome page
                    .successHandler(authSuccessHandler)
                    .failureUrl("/login?error=true")
                    .permitAll()
                    .and()
                    .logout()//build the logout portion
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))//we add in header(fragments)th:href logout,where is that point
                    .logoutSuccessUrl("/login")
                    .and()
                    .rememberMe()
                    .tokenValiditySeconds(120)//how long
                    .key("cydeo")//
                    .userDetailsService(securityService)//remember who
                    .and()
                    .build();
        }
    }


