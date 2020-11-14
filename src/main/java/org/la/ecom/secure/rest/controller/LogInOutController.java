package org.la.ecom.secure.rest.controller;

import org.la.ecom.mysql.api.dto.UserDTO;
import org.la.ecom.secure.client.service.ApiServiceSecurity;
import org.la.ecom.secure.jwt.JwtUtil;
import org.la.ecom.secure.model.dto.AuthenticationRequest;
import org.la.ecom.secure.model.dto.AuthenticationResponse;
import org.la.ecom.secure.service.CustomUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LogInOutController {

	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private CustomUserDetailsService userDetailsService;
	
	@Autowired
	private ApiServiceSecurity apiService;
	
	@Autowired
	private JwtUtil jwtTokenUtil;
	
	private final Logger log = LoggerFactory.getLogger(LogInOutController.class);
			
	@GetMapping("/hello")
	@PreAuthorize("hasRole('ROLE_USER')")
	public String getmsg() {
		return "asif";
	}
	
	@PostMapping("/hello")
	@PreAuthorize("hasRole('ROLE_ADMIN')")
	public String setmsg() {
		return "asif post";
	}
	
	@PostMapping(value = "/authenticate")
	public ResponseEntity<AuthenticationResponse> createAuthenticationToken(@RequestBody AuthenticationRequest req) {
		
		try {
			authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword()));
		}
		catch (BadCredentialsException e) {
			throw new BadCredentialsException("Incorrect username or password", e);
		}
		
		UserDetails userDetails = userDetailsService.loadUserByUsername(req.getUsername());
		
		final String jwt = jwtTokenUtil.generateToken(userDetails);
		
		return ResponseEntity.ok(new AuthenticationResponse(jwt));
		
	}
	
	@PostMapping(value = "/registration")
	public void registration(@RequestBody UserDTO userdto) {
		
		userDetailsService.addUser(userdto, "ROLE_USER");
		log.info("registration without security");
	}
	
}
