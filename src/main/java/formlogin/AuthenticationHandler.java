package formlogin;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

public class AuthenticationHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException{
        String redirect = request.getContextPath();

        if(authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))){
            redirect = "/admin";
            response.sendRedirect(redirect);
        } else if
        (authentication.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_USER"))){
            redirect = "/user";
            response.sendRedirect(redirect);
        }
    }
}
