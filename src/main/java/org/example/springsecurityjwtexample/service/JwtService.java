package org.example.springsecurityjwtexample.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.function.Function;

//Bu class tokenin icerisindeki deyerleri parse edib tapmaq ucun, siferisini qira bilmek ucun
// yada token generate etmek ucun ist edeceyim bir class olacaq

@Service
public class JwtService {

    @Value("${security.jwt.secret}")
    private String SECRET_KEY;

    public String findUsername(String jwtToken) {
        return exportToken(jwtToken, Claims::getSubject); //Subject bolumunden gotur
    }

    private <T> T exportToken(String jwtToken, Function<Claims, T> claimsResolver) {
        //Tokeni parse edirik
        final Claims claims = Jwts.parserBuilder()
                .setSigningKey(getKey())
                .build().parseClaimsJws(jwtToken).getBody();

        return claimsResolver.apply(claims);
    }

    private Key getKey() {
        byte[] key = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(key);
    }

    public boolean tokenControl(String jwtToken, UserDetails userDetails) {
        String username = findUsername(jwtToken);
        return (username.equals(userDetails.getUsername()) && !exportToken(jwtToken, Claims::getExpiration).before(new Date()));
    }

    public String generateToken(UserDetails user) {

        Date now = new Date();
        long expirationTime = now.getTime() + 864000000000L;

        return Jwts.builder()
                .setClaims(new HashMap<>())
                .setSubject(user.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(getKey(), SignatureAlgorithm.HS256)
                .compact();
    }
}
