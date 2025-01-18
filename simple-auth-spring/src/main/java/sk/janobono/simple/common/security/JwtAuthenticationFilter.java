package sk.janobono.simple.common.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import sk.janobono.simple.api.model.User;
import sk.janobono.simple.business.service.UserService;
import sk.janobono.simple.common.component.JwtToken;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtToken jwtToken;
    private final UserService userService;

    @Override
    protected void doFilterInternal(
        final HttpServletRequest httpServletRequest,
        final HttpServletResponse httpServletResponse,
        final FilterChain filterChain) throws IOException, ServletException {
        Optional.ofNullable(httpServletRequest.getHeader(HttpHeaders.AUTHORIZATION))
            .filter(s -> !s.isBlank())
            .filter(s -> s.startsWith("Bearer "))
            .map(s -> s.replace("Bearer ", ""))
            .ifPresent(token -> {
                final Long id = jwtToken.parseToken(token).id();
                final User user = userService.getUser(id);
                final List<SimpleGrantedAuthority> authorities = user.getAuthorities().stream()
                    .map(authority -> new SimpleGrantedAuthority(authority.getValue()))
                    .collect(Collectors.toList());
                SecurityContextHolder.getContext()
                    .setAuthentication(new UsernamePasswordAuthenticationToken(user, null, authorities));
            });
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
