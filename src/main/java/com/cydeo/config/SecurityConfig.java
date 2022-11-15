package com.cydeo.config;

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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Configuration//I will create a bean
public class SecurityConfig {

//    @Bean
//    public UserDetailsService userDetailsService(PasswordEncoder encoder){
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
//               .antMatchers("/user/**").hasRole("ADMIN")//localhost/need to be acces by Role Admin EVERYTHING FROM USER CONTROLLER SHOUD BE ACCESIBLE BY ADMIN
//               .antMatchers("/project/**").hasRole("MANAGER")
//               .antMatchers("/task/employee/**").hasRole("EMPLOYEE")
//               .antMatchers("/task/**").hasRole("MANAGER")//ANYONE WITH ROLE ADMIN CAN ACCES HIS OWN PAGE
              // .antMatchers("task/**").hasAnyRole("EMPLOYEE","ADMIN")
               .antMatchers("/user/**").hasAuthority("Admin")//need to put role_admin
               .antMatchers(
                       "/",
                       "/login",
                       "/fragments/**",
                       "/assets/**",
                       "/images/**"
               ).permitAll()
               .anyRequest().authenticated()
               .and()
              // .httpBasic()
               .formLogin()
               .loginPage("/login")
               .defaultSuccessUrl("/welcome")//everybody need to see welcome page
               .failureUrl("/login?error=true")
               .permitAll()
               .and().build();
   }
    }



