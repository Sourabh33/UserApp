package com.library.UserApp;

import com.library.UserApp.model.ERole;
import com.library.UserApp.model.Role;
import com.library.UserApp.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

import java.util.List;

@SpringBootApplication
public class UserAppApplication {

	@Autowired
	private RoleRepository repository;

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
	}

	public static void main(String[] args) {
		SpringApplication.run(UserAppApplication.class, args);
	}

}
