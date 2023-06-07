package org.zerock.club.security.filter;

import com.nimbusds.jwt.JWT;
import lombok.extern.log4j.Log4j2;
import net.minidev.json.JSONObject;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.zerock.club.util.JWTUtil;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Log4j2
public class ApiCheckFilter extends OncePerRequestFilter {

    /*
    오직 '/notes/..'로 시작하는 경우에만 동장하게 하기 위함

    AntPathMatcher : 앤트패턴에 맞는지를 검사하는 유틸리티
     */
    private AntPathMatcher antPathMatcher;
    private String pattern;
    private JWTUtil jwtUtil;

    public ApiCheckFilter(String pattern, JWTUtil jwtUtil) {
        this.antPathMatcher = new AntPathMatcher();
        this.pattern = pattern;
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        log.info("REQUESTURI: " + request.getRequestURI());
        log.info(antPathMatcher.match(pattern, request.getRequestURI()));

        if(antPathMatcher.match(pattern, request.getRequestURI())) {
            log.info("ApiCheckFilter........................................................");
            log.info("ApiCheckFilter........................................................");
            log.info("ApiCheckFilter........................................................");

            boolean checkHeader = checkAuthHeader(request);

            if(checkHeader) {
                filterChain.doFilter(request, response);
                return;
            } else {
                // JSONObject를 이용해서 간단한 JSON 데이터와 403 에러 메시지 만들어서 전송
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);

                // json 리턴 및 한글깨짐 수정
                response.setContentType("application.json; charset=utf-8");
                JSONObject json = new JSONObject();

                String message = "FAIL CHECK API TOKEN";
                json.put("code", "403");
                json.put("message", message);

                PrintWriter out = response.getWriter();
                out.print(json);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    /*
        특정한 Api를 호출하는 클라이언트에서는 다른 서버나 application으로 실행되기 때문에 쿠키나 세션을 활용할 수 없습니다.
        이러한 제약 때문에 api를 호출하는 경우에는 request를 전송할 때 Http 헤더 메시지에 특별한 값을 지정해서 전송합니다.

        클라이언트에서 전송한 Request에 포함된 Authorization 헤더의 값을 파악해서 사용자가 정상적인 요청인지를 알아내는 것이 Authorization 헤더의 용도입니다.
     */
    /*
        Authorization 헤더를 추출하고 헤더의 값이 맞는 경우에는 인증을 한다
     */
    private boolean checkAuthHeader(HttpServletRequest request) {
        boolean checkResult = false;

        // Authorization 헤더를 추출하고
        String authHeader = request.getHeader("Authorization");

        // Authorization 헤더 메시지의 경우 앞에는 인증 타입을 이용하는데 일반적인 경우에는 Basic을 사용하고, JWT를 이용힐 때는 'Bearer'를 사용
        if(StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            log.info("Authorization exist: " + authHeader);

            try {
                //  헤더의 값이 맞는 경우에는 인증을 한다
                String email = jwtUtil.validateAndExtract(authHeader.substring(7));

                log.info("validate result: " + email);

                checkResult = email.length() > 0;
            } catch (Exception e) {
                e.printStackTrace();
            }

//            if(authHeader.equals("12345678")) {
//                checkResult =true;
//            }
        }

        return checkResult;
    }
}
