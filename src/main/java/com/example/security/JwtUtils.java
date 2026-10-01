package com.example.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {

    private  String jwtSecret="YS1zdHJpbmctc2VjcmV0LTI1Ni1iaXRzLWxvbmc=";
    private int jwtExpirationsMs=172800000;

    public String getJwtFromHeader(){
        return "";
    }

    public String generateTokenFromUserName(String username){
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date(new Date().getTime()+jwtExpirationsMs))
                .signWith(key())
                .compact();
    }

    public boolean validateJwtToken(){
        return true;
    }

    private Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
}
