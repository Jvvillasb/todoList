package br.com.villas.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.villas.todolist.user.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter{

    @Autowired
    private UserRepository repository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

                var servletPath = request.getServletPath();

                if(servletPath.startsWith("/tasks/")){
                //Coletando Credenciais = Basic Auth
                var authorization = request.getHeader("Authorization");
                var encoded = authorization.substring("Basic".length()).trim();
                byte [] autDecoded = Base64.getDecoder().decode(encoded);
                var authString = new String(autDecoded);
                String[] credentials = authString.split(":");
                String username = credentials[0];
                String password = credentials[1];

                var user = this.repository.findByUsername(username);

                if (user == null){
                    response.sendError(401);
                }
                else {
                    var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                    if(passwordVerify.verified) {
                        request.setAttribute("idUser", user.getId());
                        filterChain.doFilter(request, response);
                    }else{
                        response.sendError(401);
                    }
                }
            }else{
                filterChain.doFilter(request, response);
            }

                
    }

    
}
