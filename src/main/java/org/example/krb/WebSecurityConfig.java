package org.example.krb;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.kerberos.authentication.KerberosServiceAuthenticationProvider;
import org.springframework.security.kerberos.authentication.sun.SunJaasKerberosTicketValidator;
import org.springframework.security.kerberos.web.authentication.SpnegoAuthenticationProcessingFilter;
import org.springframework.security.kerberos.web.authentication.SpnegoEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration("KbrWebSecurityConfig")
@Order(1)
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    protected static Logger logger = LoggerFactory.getLogger(WebSecurityConfig.class);

	@Value("${net.mosh.kerberos.service-principal}")
	private String servicePrincipal;

	@Value("${net.mosh.kerberos.keytab-location}")
	private String keytabLocation;

	@Value("${net.mosh.kerberos.enabled}")
	private boolean enabled;


	@Override
	protected void configure(HttpSecurity http) throws Exception {

        if(!enabled){
            logger.info("Kerberos disabled granting access to all request");
            http.cors().and()
                    .csrf().disable()
                    .authorizeRequests().anyRequest().permitAll();
        }else{
            logger.info("Kerberos enabled applying configurations");

            http.cors().and().csrf().disable()
					.exceptionHandling()
                    .authenticationEntryPoint(spnegoEntryPoint())
                    .and()
                    .authorizeRequests()
                    .anyRequest().authenticated()
                    .and()
                    .formLogin().loginPage("/login").permitAll()
                    .and()
                    .logout().permitAll()
                    .and()
                    .addFilterBefore(spnegoAuthenticationProcessingFilter(authenticationManagerBean()),
                            BasicAuthenticationFilter.class);
        }

		http.headers().frameOptions().sameOrigin();
	}

	/**
	 * Provide the default Spring Authentication Manager bean.
	 * This is used by the SpnegoAuthenticationProcessingFilter as
	 * part of the configuration.
	 *
	 * @return
	 * @throws Exception
	 * @see SpnegoAuthenticationProcessingFilter
	 */
	@Bean
	public AuthenticationManager anAuthenticationManager() throws Exception {
		return authenticationManager();
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(kerberosServiceAuthenticationProvider());
	}


	/**
	 * Setup SpnegoEntryPoint to point to the login
	 * page provided by the login.html page.
	 *
	 * @return
	 */
	@Bean
	public SpnegoEntryPoint spnegoEntryPoint() {
		return new SpnegoEntryPoint("/login");
	}

	/**
	 * SpnegoAuthenticationProcessingFilter:
	 * <p>
	 * This is your friendly SSO filter, that kindly automatically
	 * logs the user in if the Browser provides the actual credentials
	 *
	 * @param authenticationManager - with BeanIds.AUTHENTICATION_MANAGER
	 * @return
	 * @See AuthenticationManager
	 */
	@Bean
	public SpnegoAuthenticationProcessingFilter spnegoAuthenticationProcessingFilter(
			AuthenticationManager authenticationManager) {
		SpnegoAuthenticationProcessingFilter filter = new SpnegoAuthenticationProcessingFilter();
		filter.setAuthenticationManager(authenticationManager);
		return filter;
	}

	/**
	 * KerberosServiceAuthenticationProvider:
	 * <p>
	 * This bean is needed by the global AuthenticationManager bean as the only
	 * accepted authentication providers.
	 * <p>
	 * To actually provide Spring Security with the required user details the
	 * KerberosUserDetailsService is provided to the service auth provider.
	 * <p>
	 *
	 * @return - A configured Kerberos Service Auth Provider
	 * @see SunJaasKerberosTicketValidator
	 * @see KerberosUserDetailsService
	 */
	@Bean
	public KerberosServiceAuthenticationProvider kerberosServiceAuthenticationProvider() {
		KerberosServiceAuthenticationProvider provider = new KerberosServiceAuthenticationProvider();
		provider.setTicketValidator(sunJaasKerberosTicketValidator());
		provider.setUserDetailsService(userDetailsService());
		return provider;
	}

	/**
	 * SunJaasKerberosTicketValidator
	 * <p>
	 * This bean will on behalf of the web application validate the visiting users provided
	 * Kerberos Ticket. This will not kick in if the underlying JAAS and KRB5 configuration is
	 * not working as expected.
	 * <p>
	 * Find the values of the servicePrincipal and keytabLocation in application.properties
	 *
	 * @return - A Kerberos Ticket Validator
	 */
	@Bean
	public SunJaasKerberosTicketValidator sunJaasKerberosTicketValidator() {
		SunJaasKerberosTicketValidator ticketValidator = new SunJaasKerberosTicketValidator();
		ticketValidator.setServicePrincipal(servicePrincipal);
		ticketValidator.setKeyTabLocation(new FileSystemResource(keytabLocation));
		ticketValidator.setDebug(true);
		return ticketValidator;
	}

	@Bean
	public KerberosUserDetailsService userDetailsService() {
		return new KerberosUserDetailsService();
	}

}
