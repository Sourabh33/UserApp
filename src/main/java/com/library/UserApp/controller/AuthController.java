package com.library.UserApp.controller;

import com.library.UserApp.exception.JwtAuthException;
import com.library.UserApp.model.ERole;
import com.library.UserApp.model.User;
import com.library.UserApp.payload.response.LoginMessageResponse;
import com.library.UserApp.payload.response.MessageResponse;
import com.library.UserApp.repository.UserRepository;
import com.library.UserApp.security.services.AuthenticationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/api/auth")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationService authenticationService;

    @GetMapping("/all-users")
    public ResponseEntity<List<User>> getAllUserDetails() {
        return ResponseEntity.ok(authenticationService.getAllUserDetail());
    }

    @GetMapping("/validate")
    public ResponseEntity<?> checkJwtValidation(@RequestParam String accessToken) {
        try {
            if (authenticationService.validateJwtToken(accessToken)) {
                return ResponseEntity.ok(new MessageResponse("Valid", true));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Invalid", false));
            }
        } catch (JwtAuthException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse(e.getMessage(), false));
        }
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestParam String username, @RequestParam String password) {
        logger.info("login request: {}", username);
        try {
            LoginMessageResponse response = new LoginMessageResponse("Logged in successfully", true, authenticationService.signInUser(username, password));
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new LoginMessageResponse("Invalid credentials", false, null));
        }
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestParam String username,
                                          @RequestParam String email,
                                          @RequestParam String password,
                                          @RequestParam(required = false, defaultValue = "ROLE_USER") ERole newRole) {
        if (userRepository.existsByUsername(username)) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!", false));
        }
        if (userRepository.existsByEmail(email)) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Email is already in use!", false));
        }

        try {
            User user = new User(username, email, password);
            if (authenticationService.signUpUser(user, newRole)) {
                return ResponseEntity.ok(new MessageResponse("User registered successfully!", true));
            } else {
                return ResponseEntity.badRequest().body(new MessageResponse("Error: Not able to register", false));
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Not able to register", false));
        }

    }

}
