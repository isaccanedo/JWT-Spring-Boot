## Autenticação com JWT no Spring Boot

# 1. Introdução

JSON Web Token (JWT), é um padrão que define uma forma segura de transmitir mensagens utilizando um token compacto e self-contained no formato de um objeto JSON.

É compacto porque além de leve, pode ser enviado através de um HTTP header, via URL, ou como parâmetro no corpo de uma requisição HTTP. Dizemos que um JWT é self-contained porque seu payload possui toda informação necessária para autenticar um usuário, assim, não é necessário fazer mais que uma única consulta na base de dados.

JSON Web Tokens são comumente utilizados quando precisamos de autenticação em aplicações com arquiteturas stateless (REST por exemplo). JWTs nos permitem autenticar um usuário e garantir que as demais requisições serão feitas de forma autenticada, sendo possível restringir acessos a recursos e serviços com diferentes níveis de permissões.

# 2. Estrutura do JSON Web Token

Um JWT é composto por três partes separadas por ponto.

hhh.ppp.sss

```
- H eader;
- P ayload;
- S ignature;
```

### 2.1. Header 

consiste em duas partes diferentes: o tipo do token (no caso JWT), e o nome do algorítimo responsável pelo hashing, HMAC SHA256 ou RSA.

```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

Esse JSON será encoded via Base64Url e irá compor a primeira parte do token.

### 2.2. Payload 

Contém o que chamamos de claims. Claims são atributos da entidade (no caso usuário) e metadados. Um exemplo de payload:

```
{
  "sub": "1234",
  "name": "Isac Canedo",
  "admin": true
}
```

Essse JSON será encoded via Base64Url e irá compor a segunda parte do token.

### 2.3. Signature
Verifica que o remetente do JWT é quem diz ser para garantir que a mensagem não foi alterada durante o tráfego. Para criar a assinatura (signature), utiliza-se o header Base64 encoded, o payload também Base64 encoded, e o algorítimo especificado no header. Utilizando o algorítimo HMAC SHA256, a signature ficaria assim:

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret)
```

Por fim teremos uma String em Base64 separada por pontos, compondo o JSON Web Token.

```
eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhZG1pbiIsImV4cCI6MTQ5MTUyMjg2NH0.OZQPWEgs-JaABOCEodulSiN-yd-T1gmZzrswY4kaNKNI_FyOVFJPaBsAqkcD3SgN010Y4VSFSNh6DXNqHwNMIw
```

Para testar esses conceitos e montar um JWT, você pode usar o JWT Debugger e ver o token sendo formado na prática.

# 3. Criando o projeto Spring boot

A ideia é implementar autenticação para uma aplicação Springboot. Para criar um novo projeto spring boot basta acessar https://start.spring.io/ e no campo “dependencies”, adicionar apenas “Web”. Fazendo isso, um novo projeto pronto para ser executado será criado já com todas as dependências que precisamos para executar a aplicação.

Feito isso, criaremos uma rota /home para verificarmos o funcionamento correto da nossa aplicação, mais tarde criaremos outras rotas. Quando queremos criar métodos que representem endpoints no Spring, precisamos criar um RestController. Por hora, vamos adicionar o endpoint na única classe que temos no projeto, a classe principal.

```
package com.isaccanedo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
@EnableAutoConfiguration
public class isaccanedoApplication {

	public static void main(String[] args) {
		SpringApplication.run(isaccanedoApplication.class, args);
	}
	
	@RequestMapping("/home")
	public String hello() {
		return "Hello Isac Canedo";
	}
}
```

Executando o método main, acessando o endereço localhost:8080/home devemos ver a mensagem "Hello Isac Canedo!".

Agora vamos extender um pouco mais, criando a classe UserController. Essa classe também será anotada com @RestController, vamos mapear a URL /users retornando um JSON simples quando ela for acessada.

```
package com.isaccanedo.controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

	@RequestMapping("/users")
	@ResponseBody
	public String getUsers() {
		return "{\"users\":[{\"name\":\"Isac\", \"country\":\"Brazil\"}," +
		           "{\"name\":\"Canedo\",\"country\":\"Brazil\"}]}";
	}
}
```

Como fizemos na nossa classe principal, aqui também criamos um endpoint. A diferença é que nosso método retorna um JSON. Por essa razão adicionamos`` a anotação @ResponseBody. Com essa anotação, quando uma requisição especificar em seu header que aceita application/json , os dados serão retornados para o client em formato JSON.

```
{"users":[{"name":"Isac", "country":"Brazil"},{"name":"Canedo","country":"Brazil"}]}
```

# 4. Adicionando segurança às rotas

Até esse momento, os recursos da nossa aplicação estão expostos para todos. Qualquer pessoa pode acessar a lista de usuários do nosso servidor. Para que esse recurso seja restrito apenas a usuários autenticados, vamos adicionar segurança à nossa aplicação com JSON Web Tokens!

Nesse exemplo, vamos expor publicamente apenas os recursos disponíveis em /home e /login. Para acessar /users será necessário que o usuário envie ao nosso servidor um token JWT válido. Para isso, vamos adicionar duas dependências ao pom.xml. A primeira é spring-boot-starter-security que nos permite trabalhar com autenticação no Spring, e a segunda, é jjwt que vai gerenciar nossos JWTs.

```
<dependencies>
	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-web</artifactId>
	</dependency>

	<dependency>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-test</artifactId>
		<scope>test</scope>
	</dependency>

	<dependency>
	    <groupId>org.springframework.boot</groupId>
	    <artifactId>spring-boot-starter-security</artifactId>
	</dependency>

	<dependency>
	    <groupId>io.jsonwebtoken</groupId>
	    <artifactId>jjwt</artifactId>
	    <version>0.7.0</version>
	</dependency>
</dependencies>
```

Adicionadas as dependências, a primeira coisa que queremos fazer é deixar de expor os recursos de /users publicamente. Por tanto, vamos criar uma configuração que restrinja esse acesso criando uma nova classe chamada WebSecurityConfig. Essa nova classe vai ser uma classe filha da classe WebSecurityConfigurerAdapter do Spring security. Nesse exemplo, vamos cria-la em um novo pacote com.isaccanedo.security.

```
package com.isaccanedo.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		httpSecurity.csrf().disable().authorizeRequests()
			.antMatchers("/home").permitAll()
			.antMatchers(HttpMethod.POST, "/login").permitAll()
			.anyRequest().authenticated()
			.and()
			
			// filtra requisições de login
			.addFilterBefore(new JWTLoginFilter("/login", authenticationManager()),
	                UsernamePasswordAuthenticationFilter.class)
			
			// filtra outras requisições para verificar a presença do JWT no header
			.addFilterBefore(new JWTAuthenticationFilter(),
	                UsernamePasswordAuthenticationFilter.class);
	}
	
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		// cria uma conta default
		auth.inMemoryAuthentication()
			.withUser("admin")
			.password("password")
			.roles("ADMIN");
	}
}
```

Aqui estamos usando anotações do Spring Security e do próprio Spring Boot. 

Nessa classe definimos que todos podem acessar /home, e que o endpoint /login está disponível apenas via requisições do tipo POST. Para todas as demais rotas a autenticação é necessária. Não se preocupe com erros de compilação, já que ainda não criamos as classes JWTLoginFilter e JWTAuthenticationFilter. Vamos cria-las em breve. Elas serão as classes responsáveis por filtrar as requisições feitas em /login e em todas as outras rotas, para decidir como essas requisições deverão ser tratadas. Repare que também adicionamos uma conta default aqui, para testarmos o funcionamento da autenticação.

Uma grande vantagem de estarmos utilizando o Spring boot aqui, é que em momento algum foi necessário mudar o código já existente das rotas, nem adicionar arquivos .xml de configuração! Tudo foi feito pragmaticamente com uma classe de configuração anotada com @Configuration.

As classes JWTLoginFilter e JWTAuthenticationFilter serão responsáveis por lidar com login e validação da autenticação dos usuários quando acessarem outras rotas. Por tanto, antes nos preocuparmos com elas, vamos ter que criar as classes que irão lidar com os JWTs.


# 5. Criando os JWT Services no Spring boot

Nossos JWT services serão responsáveis por gerara e validar nossos JWT tokens. Nesse exemplo vamos criar um token baseado em username e um expiration_time, em seguida iremos assiná-lo com uma palavra chave secret.

Para criar e verificar nossos tokens, vamos criar a classe TokenAuthenticationService dentro do mesmo pacote com.isaccanedo.security. Nela vamos utilizar a classe que incluímos como dependência io.jsonwebtoken.Jwts para validar os tokens.

```
package com.isaccanedo.security;

import java.util.Collections;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenAuthenticationService {
	
	// EXPIRATION_TIME = 10 dias
	static final long EXPIRATION_TIME = 860_000_000;
	static final String SECRET = "MySecret";
	static final String TOKEN_PREFIX = "Bearer";
	static final String HEADER_STRING = "Authorization";
	
	static void addAuthentication(HttpServletResponse response, String username) {
		String JWT = Jwts.builder()
				.setSubject(username)
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
				.signWith(SignatureAlgorithm.HS512, SECRET)
				.compact();
		
		response.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + JWT);
	}
	
	static Authentication getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_STRING);
		
		if (token != null) {
			// faz parse do token
			String user = Jwts.parser()
					.setSigningKey(SECRET)
					.parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
					.getBody()
					.getSubject();
			
			if (user != null) {
				return new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());
			}
		}
		return null;
	}
	
}
```

# 6. Autenticando os JWTs

Já temos tudo que precisamos para usar os JWTs no processo de autenticação. Agora vamos criar a classe JWTLoginFilter para interceptar as requisições do tipo POST feitas em /login e tentar autenticar o usuário. Quando o usuário for autenticado com sucesso, um método irá retornar um JWT com a autorização Authorization no cabeçalho da resposta.

```
package com.isaccanedo.security;

import java.io.IOException;
import java.util.Collections;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;

public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

	protected JWTLoginFilter(String url, AuthenticationManager authManager) {
		super(new AntPathRequestMatcher(url));
		setAuthenticationManager(authManager);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		
		AccountCredentials credentials = new ObjectMapper()
				.readValue(request.getInputStream(), AccountCredentials.class);
		
		return getAuthenticationManager().authenticate(
				new UsernamePasswordAuthenticationToken(
						credentials.getUsername(), 
						credentials.getPassword(), 
						Collections.emptyList()
						)
				);
	}
	
	@Override
	protected void successfulAuthentication(
			HttpServletRequest request, 
			HttpServletResponse response,
			FilterChain filterChain,
			Authentication auth) throws IOException, ServletException {
		
		TokenAuthenticationService.addAuthentication(response, auth.getName());
	}

}
```

Aqui o método attemptAuthentication é quem lida com a tentativa de autenticação. Pegamos o usernamee password da requisição, e utilizamos o AuthenticationManager para verificar se os dados são correspondentes aos dados do nosso usuário existente. Caso os dados estejam corretos, invocamos o método successfulAuthentication para enviar ao service TokenAuthenticationService o username do usuário para que este service adicione um JWT à nossa resposta (response).

Agora sim, criaremos a classe JWTAuthenticationFilter.

```
package com.isaccanedo.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class JWTAuthenticationFilter extends GenericFilterBean {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		
		Authentication authentication = TokenAuthenticationService
				.getAuthentication((HttpServletRequest) request);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		filterChain.doFilter(request, response);
	}

}
```

Nessa classe validamos a existência de um JWT nas requisições, com ajuda do service TokenAuthenticationService.

Agora só falta criarmos a classe AccountCredentials, que será utilizada para enviarmos as credenciais da conta a ser validada quando fizermos requisições do tipo POST à URL /login. Requests de login portanto, devem ser feitas com um objeto do tipo AccountCredentials em seu body.

```
package com.isaccanedo.security;

public class AccountCredentials {
	
	private String username;
	private String password;
	
	public String getUsername() {
		return username;
	}
	
	public void setUsername(String username) {
		this.username = username;
	}
	
	public String getPassword() {
		return password;
	}
	
	public void setPassword(String password) {
		this.password = password;
	}
}
```

# 7. Executando a autenticação

Nossa aplicação agora está segura e podemos realizar autenticações com JWT! Após reiniciar a aplicação vamos tentar acessar o endereço http://localhost:8080/users. Se tudo estiver funcionando corretamente, a resposta deve ser Access Denied.

Para nos autenticarmos corretamente, vamos enviar uma requisição do tipo POST para o endereço http://localhost:8080/login com as credencias do nosso usuário default no body. Usando o Postman a requisição feita com sucesso deve se parecer com isso:

No header da resposta dessa requisição temos nosso token com o prefixo Bearer. Para buscar os usuários, agora precisamos enviar no header da requisição nosso token incluindo o cabeçalho Authorization com o JWT que recebemos quando realizamos a autenticação com sucesso.