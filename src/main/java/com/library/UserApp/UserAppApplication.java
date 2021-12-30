package com.library.UserApp;

import com.library.UserApp.model.ERole;
import com.library.UserApp.model.Role;
import com.library.UserApp.model.User;
import com.library.UserApp.repository.RoleRepository;
import com.library.UserApp.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;
import java.util.List;

@SpringBootApplication
public class UserAppApplication {

	@Autowired
	private RoleRepository repository;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private PasswordEncoder encoder;

	@EventListener(ApplicationReadyEvent.class)
	public void loadData() {

		List<Role> roles = repository.findAll();
		if(roles.isEmpty()) {
			Role role1 = new Role(ERole.ROLE_USER);
			Role role2 = new Role(ERole.ROLE_MODERATOR);
			Role role3 = new Role(ERole.ROLE_ADMIN);

			repository.save(role1);
			repository.save(role2);
			repository.save(role3);
		}

		// admin user
		User user = new User();
		user.setId(1L);
		user.setUsername("Sourabh33");
		user.setPassword(encoder.encode("Sourabh@123"));
		user.setEmail("sourabh33@gmail.com");
		user.setRoles(Collections.singleton(new Role(ERole.ROLE_ADMIN)));

		userRepository.save(user);
	}

	public static void main(String[] args) {
		SpringApplication.run(UserAppApplication.class, args);
	}

}
