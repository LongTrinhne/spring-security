package com.example.security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {
    private static final String SECRET_KEY = "RiIL8ZUj5hyaVZNgdjPIJBEeW89eWMvH8SHUt16B1twmwCvT+t3RY8HIIDhTmH8RPMubG9TaYvMs8iDoUIaem905LH/mqLFuhr6rXU5ybIy6+FGcUluENGGsFHTSSn+YqJ2RvzP48t79wzQO1GsK26FS8LeICuMIJN4rw9f1bt+/HtI4NULKB96Kx+OCy8j3OOr4iooqriit0PxCX772S42pXkSmlqxPYsUsV6WtdgdjWy9POdUIoIOl9MHuLor9qxqILA6znBvIDRdUnLkSUJFRL4gLbW7Hb4Op5zavCyJdHOW9HAxUxNP1wv9DTdnALSKPlp1aZsJcHQaHbfD9LAND56aQyvNUrZrrHj7UpQg";

    public String extractUsername(String jwtToken) {
        return extractClaim(jwtToken, Claims::getSubject);
    }
    // extract single claim: Trich xuat
    public <T> T extractClaim (String token, Function<Claims, T> claimsResolver) {
        Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    // extract all claims
    private Claims extractAllClaims(String jwtToken) {
        return Jwts
                .parserBuilder() // To validate or parse the JWT token : phan tich token
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(jwtToken)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyByte = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyByte);
    }

    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Objects> extraClaims, UserDetails userDetails) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis())) // when this claim is created, check ì the token is valid or not
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 24 * 60)) // how long this token should be valid
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean isTokenValid(String jwtToken, UserDetails userDetails) {
        String username = extractUsername(jwtToken);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(jwtToken);
    }
    private Date extractExpiration(String jwtToken) {
        return extractClaim(jwtToken, Claims::getExpiration);
    }
    private boolean isTokenExpired(String jwtToken) {
        return extractExpiration(jwtToken).before(new Date());
    }



}
