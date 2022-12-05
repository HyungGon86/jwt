package study.jwt.config.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import study.jwt.model.User;
import study.jwt.repository.UserRepository;

// http://localhost:8080/login => 여기서 동작을 안한다. 폼 로그인을 안쓴다고 해놧기때문
@Service
@RequiredArgsConstructor
public class PrincipalDetailService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User userEntity = userRepository.findByUsername(username);
        return userEntity != null ? new PrincipalDetails(userEntity) : null;
    }
}
