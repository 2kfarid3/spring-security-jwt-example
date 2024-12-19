package org.example.springsecurityjwtexample.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.example.springsecurityjwtexample.service.JwtService;
import org.example.springsecurityjwtexample.token.TokenRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

///Bu class http isteklerini filtirleyen bir class olacaq
///OncePerRequestFilter-in metodu sayesinde http request ve response -larin isteyine cavab vermek ucun istifade edeceyik
///Http cavabi yaradib, bunun icinde var olacaq problemleri yada token-in dogrulugunda token-in getmesi gereken yere getmesine icaze vereceyik

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    private final UserDetailsService userDetailsService;

    private final TokenRepository tokenRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        ///Bize request gelir ve bunun headerinde Authorization olur
        final String header = request.getHeader("Authorization");
        final String jwtToken;
        final String username;

        ///Birinci gelen isteyin jwt olub-olmadigini yoxlayiriq
        if (header == null || !header.startsWith("Bearer ")) {
            filterChain.doFilter(request, response); ///Client terefinden gelen deyeri geri gonder
            return;
        }


        jwtToken = header.substring(7);
        username = jwtService.findUsername(jwtToken);

                                  ///Oturum acilmayib ve ya her hansi giris edilmeyibse
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                var isValidToken = tokenRepository.findByToken(jwtToken)
                        .map(token -> !token.isExpired() && !token.isRevoked())
                        .orElse(false);
                if (jwtService.tokenControl(jwtToken, userDetails) && isValidToken) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken
                            (userDetails, null, userDetails.getAuthorities()); ///User-in bilgilerini authentication obyekti icinde tuturuq
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request)); ///Elave detaylar add edirik(ip adresi ve ya browser bilgileri ola biler)
                    SecurityContextHolder.getContext().setAuthentication(authentication); ///Obyekti save edirik
                }
            }
            filterChain.doFilter(request, response);
    }
}
