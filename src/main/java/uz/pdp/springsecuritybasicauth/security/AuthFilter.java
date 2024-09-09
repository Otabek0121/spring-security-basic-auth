package uz.pdp.springsecuritybasicauth.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import uz.pdp.springsecuritybasicauth.entity.User;
import uz.pdp.springsecuritybasicauth.repository.UserRepository;

import java.io.IOException;
import java.util.Base64;
import java.util.HashSet;
import java.util.Optional;
import java.util.logging.Filter;



@Component
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {



    /**
     * Bunday yo'lda inject qilish kerak emas buni service ga bog'lash kerak
     * bu ketmonskiy yo'l
     */
    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        System.out.println("Hello filter");

        /**
         * Headerdan Bsic (encodlangan( username:password )) ni olish uchun kerak
         * <p>
         * uni decodlab username vs passwordini olish kerak
         *
         * bu yerda headerdagi Authorization keyli malumotni value qismi olinadi
         */

        String authorization = request.getHeader("Authorization");


        /**
         * Basic auth da  username and pasword headerda encodlani b keladi
         * Key value ko'rinishida
         *
         * key--> Authorization
         *
         * value :  Basic encodlangan-->( username:password)
         * "Basic " string ni qriqib qolgan qismini dekodlash kerak;
         */
        UserDetails userDetails = getUserByBasicAuth(authorization);

        /**
         * SecurityContextHolder - ( ApplicationContext- bu beanlarni saqlasa)
         * bu securityga tegishli bo'lgan elementlarni saqlab turadi
         * .getContext()- method i  Hozirgi kirib turgan userni olib beradi(current user)
         * .getAuthentication() - method i esa
         * .setAuthentication() - method i esa (authentication qabul qiladi u interface)
         * uni new qilib berib yubora olmaymiz uni bolasini berib yuboramiz yani UsernamePasswordAuthenticationToken ni
         *
         * uni yaratishda 3 ta yoki 2 ta field berish kerak
         * principal -> username (userni yoki userDetails ni bersak ham bo'ladi)
         * credentials-> password (null bersak ham bo'ladi)
         * Collection <A extends GrandAuthority> bu uni rollari permissionlari berilsa bo'ladi
         *
         */

        if(userDetails!=null){
            /**
             * agar kodim bu yergacha tushmasa yani pastdagi kod ishlamasa
             * spring bu user authenticat siyadan o'tganini bilmaydi
             * authentcatsiyadan o'tqiz degani shu
             *
             */

            Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, new HashSet<>());

            System.out.println(SecurityContextHolder.getContext().getAuthentication());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            System.out.println(SecurityContextHolder.getContext().getAuthentication());
        }



        filterChain.doFilter(request,response);

    }

    private UserDetails getUserByBasicAuth(String authorization) {
        authorization = authorization.substring("Basic ".length());
        byte[] decode = Base64.getDecoder().decode(authorization);

        String[] split = new String(decode).split(":");
        String username=split[0];
        String password=split[1];

        Optional<User> optionalUser =
                userRepository.findByEmail(username);


        if(optionalUser.isEmpty())
            return null;


        User user = optionalUser.get();


        /**
         * heshlanib saqlangan passwordlarni tekshirish uchun
         * @SecurityConfig ni ichida PasswordEncoder
         * ni bean qilib olamiz
         */
        if (!passwordEncoder.matches(password, user.getPassword())) {
            return null;
        }


        /**
         * Tepada UserDetails qaytarganimni sababi
         * bu yerda springni User classini buil qilganda
         * u userDetails qaytaradi.
         */

        return org.springframework.security.core.userdetails.User.builder()
                .password(user.getPassword())
                .username(user.getEmail())
                .build();

    }
}
