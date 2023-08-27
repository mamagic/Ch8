package tacos.security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private final UserDetailsService userService;
	private final JsonLoginProcessFilter jsonLoginProcessFilter;
	
	public SecurityConfig(@Lazy UserDetailsService userService, @Lazy JsonLoginProcessFilter jsonLoginProcessFilter) {
		this.userService = userService;
		this.jsonLoginProcessFilter = jsonLoginProcessFilter;
	}
	

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {

		httpSecurity.authorizeHttpRequests() // HttpServletRequest를 사용하는 요청들에 대한 접근제한을 설정하겠다.
				.requestMatchers(HttpMethod.OPTIONS).permitAll() // needed for Angular/CORS
				.requestMatchers(HttpMethod.POST, "/api/ingredients").permitAll()
				.requestMatchers("/design", "/orders/**", "/login").permitAll() // 로그인 api
				// .access("hasRole('ROLE_USER')")
				.requestMatchers(HttpMethod.PATCH, "/ingredients").permitAll() // 회원가입 api
				.requestMatchers("/**").permitAll()

//              .and()
//               	.formLogin()
//               		.usernameParameter("username") //화면단에서 받는 이메일과 패스워드 설정
//               		.passwordParameter("password")
//               		.loginProcessingUrl("/login")
//               		.defaultSuccessUrl("/")

				.and().httpBasic().realmName("Taco Cloud")

				.and().logout().logoutSuccessUrl("/")

				.and().csrf().ignoringRequestMatchers("/ingredients/**", "/design", "/orders/**", "/api/**")

				// Allow pages to be loaded in frames from the same origin; needed for
				// H2-Console
				.and().headers().frameOptions().sameOrigin();
		httpSecurity.addFilterAfter(jsonLoginProcessFilter, LogoutFilter.class);

		httpSecurity.httpBasic().disable();
		httpSecurity.csrf().disable(); // 외부 POST 요청을 받아야하니 csrf는 꺼준다.
		httpSecurity.cors(); // ⭐ CORS를 커스텀하려면 이렇게
		httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

		httpSecurity.authorizeHttpRequests().requestMatchers("/**").permitAll().anyRequest().authenticated();
		return httpSecurity.build();
	}

	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() throws Exception {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userService);
		provider.setPasswordEncoder(bCryptPasswordEncoder());

		return provider;
	}
	
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
		return configuration.getAuthenticationManager();
	}
	

//	@Bean
//	public JsonLoginProcessFilter jsonLoginProcessFilter() {
//		JsonLoginProcessFilter jsonLoginProcessFilter = new JsonLoginProcessFilter(objectMapper, authenticationManager);
//		jsonLoginProcessFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
//			response.getWriter().println("Success Login");
//		});
//		return jsonLoginProcessFilter;
//	}


	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Configuration
	public class CorsConfig {

		@Bean
		public CorsConfigurationSource corsConfigurationSource() {
			CorsConfiguration config = new CorsConfiguration();

			config.setAllowCredentials(true);
			config.setAllowedOrigins(List.of("http://localhost:4200"));
			config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
			config.setAllowedHeaders(List.of("*"));
			config.setExposedHeaders(List.of("*"));

			UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
			source.registerCorsConfiguration("/**", config);
			return source;
		}

	}
}
