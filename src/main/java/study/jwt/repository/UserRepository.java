package study.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import study.jwt.model.User;

public interface UserRepository extends JpaRepository<User, Long> {

    User findByUsername(String username);
}
