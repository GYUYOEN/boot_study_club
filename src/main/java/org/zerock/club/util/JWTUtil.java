package org.zerock.club.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.DefaultClaims;
import io.jsonwebtoken.impl.DefaultJws;
import lombok.extern.log4j.Log4j2;

import java.time.ZonedDateTime;
import java.util.Date;

@Log4j2
public class JWTUtil {
    private String secretKey = "zerock12345678";

    // 1 month
    private long expire = 60*24*30; // 만료기간

    // JWT 토큰을 생성하는 역할
    public String generateToken(String content) throws Exception {
        return Jwts.builder()
                .setIssuedAt(new Date())
//                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(expire).toInstant()))
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(1).toInstant()))
                .claim("sub", content) // 'sub'라는 이름을 가지는 Claim에는 사용자의 이메일 주소를 입력해 주어서 나중에 사용할 수 있도록 구성
                .signWith(SignatureAlgorithm.HS256, secretKey.getBytes("UTF-8"))
                .compact();
    }

    // 인코딩된 문자열애서 원하는 값을 추출하는 용도로 작성
    // JWT 문자열을 검증하는 역할
    public String validateAndExtract(String tokenStr) throws Exception {
        String contentValue = null;

        try {
            DefaultJws defaultJws = (DefaultJws) Jwts.parser().setSigningKey(secretKey.getBytes("UTF-8")).parseClaimsJws(tokenStr);

            log.info(defaultJws);
            log.info(defaultJws.getBody().getClass());

            DefaultClaims claims = (DefaultClaims) defaultJws.getBody();

            log.info("-------------------------------------");

            contentValue = claims.getSubject();
        } catch (Exception e) {
            e.printStackTrace();
            log.error(e.getMessage());
            contentValue = null;
        }
        return contentValue;

    }
}
