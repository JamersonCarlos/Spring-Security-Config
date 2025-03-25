# Spring-Security-Config
Esse repositório tem como objetivo servir de template para criação de outras aplicações que utilizem autenticação. 

## 🛠️Tecnologias Utilizadas

Spring Boot (versão 2.7 ou superior)

Spring Security

JWT (JSON Web Token)

JPA/Hibernate

MySQL (localmente ou em contêiner Docker)

Docker (para execução do banco de dados)

Maven (gerenciador de dependências)

## ♻️**Pré-requisitos**

Antes de iniciar, certifique-se de ter os seguintes programas instalados em sua máquina:

Java JDK 17 ou superior

Maven (para compilar e gerenciar dependências do projeto)

Docker (para execução do MySQL em contêiner)

MySQL (caso não utilize Docker)

## ⚡**Passo a Passo para Configuração**

### Realizar configuração necessária para se autenticar ao banco de dados 
No arquivo application.properties utilize as variáveis a seguir:
```
spring.datasource.url=jdbc:mysql://localhost:3306/nome_do_banco
spring.datasource.username=root
spring.datasource.password=senha_do_banco
spring.jpa.hibernate.ddl-auto=update
spring.security.jwt.secret=seuSegredoAqui
```

### Criar o modelo de Usuário que deseja adicionar a sua aplicação 
Para alguns casos será essencial a utilização de roles para limitar acesso a determinados serviços 
oferecidos pela aplicação, em outros casos podem não ser necessários, portanto a configuração com utilização
de roles, ficará da seguinte maneira: 

```
@Entity
@Table(name="users")
public class User implements UserDetails {

    
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id; 

    private String name; 
    private String login; 
    private String password; 


    @Enumerated(EnumType.STRING)
    private Role role;
    
    public User(String name, String login, String password, Role role) {
        this.name = name;
        this.login = login;
        this.password = password;
        this.role = role;
    }

    //Métodos extendidos do UserDetails
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if(this.role == Role.ADMIN) return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER")); 
        else return List.of(new SimpleGrantedAuthority("ROLE_USER"));
    }

    @Override
    public String getUsername() {
        return login;
    }
    
    .
    .
    .
    //Métodos Get e Set do nosso modelo
}
```

Onde as roles são listadas e definidas utilizando um Enumerate, evitando que seja criado usuários com roles não existentes. 

### Criar uma interface para acessar e manipular informações do banco de dados  
Toda vez que algum serviço for realizar alguma ação no banco de dados será por meio dessa interface. 

```
@Repository
public interface UserRepository extends JpaRepository<User, String>{
    UserDetails findByLogin(String login);  
}
```

### Criar serviço para autenticação via spring security 

```
@Service
public class AuthorizationService implements UserDetailsService{

    @Autowired
    UserRepository repository; 
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByLogin(username); 
    }
   
}
```
### Configurar a corrente de filtros ou SecurityFilterChain
Responsável por implementar filtros a requisição realizada por um cliente, para realizar o controle de acesso. Esses são implementados utilizando métodos 
com uma annotation @bean para dizer ao spring que se trata de uma configuração. 

**Template base para criação da classe de configurações de segurança**
```
@Configuration
@EnableWebSecurity
public class SecurityConfigurations {}
```

**Método para realizar os filtros de segurança**
```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)throws Exception { 
    return httpSecurity 
        .csrf(csrf-> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers("/auth/login").permitAll()
            .requestMatchers("/auth/register").permitAll()
            .requestMatchers(HttpMethod.POST, "/").hasRole("USER")
            .anyRequest().authenticated()
        )
        .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
        .build(); 
}
```

Ainda na classe de configuração para segurança da autenticação, temos dois métodos um para fornecer acesso a configuração de autenticação 
do spring security 

```
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception { 
    return authenticationConfiguration.getAuthenticationManager();
}
```
O outro método é responsável por fornecer uma interface de encriptação da senha do usuário. 
``` 
@Bean
public PasswordEncoder passwordEncoder() { 
    return new BCryptPasswordEncoder();
}
```

### Rota para registrar um usuário 
Essa rota é responsável por verificar se o usuário já existe no banco de dados, caso não exista, realiza o cadastro de um novo usuário.

```
@PostMapping("/register")
public ResponseEntity<?> register(@RequestBody RegisterDTO data) {
    if(this.userRepository.findByLogin(data.login()) != null) throw new UserAlreadyExistsException("O usuário com login '" + data.login() + "' já existe."); 

    //Criptografando a senha do usuário e salvando no banco de dados
    String encryptedPassword = new BCryptPasswordEncoder().encode(data.password()); 
    User newUser = new User(data.name(), data.login(), encryptedPassword, data.role());
    this.userRepository.save(newUser);
    
    return ResponseEntity.ok().build();
}
```

### Criar serviço para criação e validação de Tokens  
A geração de tokens é realizada por meio de uma biblioteca JWT, utilizando um algoritmo específico associado a uma chave secreta para garantir a unicidade do token. Sem essa chave, aplicações que empregam o mesmo algoritmo poderiam gerar hashes idênticos para senhas iguais. No entanto, ao incorporar a chave secreta no processo, adicionamos um elemento único à geração do token, aumentando sua segurança. Por isso, essa chave deve ser armazenada com extremo cuidado.

O primeiro passo é criar um serviço utilize a anotation @service, dentro desse serviço teremos dois métodos: 

**Método para gerar um token**
```
@Value("${api.security.token.secret}")
private String secret; 

//Define qual o tempo para o token expirar
private Instant genExpirationDate() { 
    return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
}

//Gera o token com base no algorithm definido
public String generateToken(User user) { 
    try {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        String token = JWT.create()
            .withIssuer("SICTEC")
            .withSubject(user.getLogin())
            .withExpiresAt(genExpirationDate())
            .sign(algorithm);
        return token; 
    } catch (JWTCreationException e) {
        throw new RuntimeException("Error while generating token", e );
    }
}
```

**Método para validar um token**
```
public String validateToken(String token) { 
    try {
        Algorithm algorithm = Algorithm.HMAC256(secret);
        return JWT.require(algorithm)
                .withIssuer("auth-api")
                .build()
                .verify(token)
                .getSubject(); 
    } catch (JWTVerificationException e) {
        return "";
    }
}
```

## Filtro para todas as requisições 
É necessário criar uma classe para realizar esse filtro em todas as requisições, principalmente para as rotas que necessita de autenticação. 
```
@Component
public class SecurityFilter extends OncePerRequestFilter {

    @Autowired
    TokenService tokenService; 

    @Autowired 
    UserRepository userRepository; 

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
            var token = this.recoveryToken(request);
            if(token != null) { 
                var login = tokenService.validateToken(token);
                UserDetails user = userRepository.findByLogin(login);
                var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());   
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
            filterChain.doFilter(request, response);
    }

    private String recoveryToken(HttpServletRequest request) { 
        var authHeader = request.getHeader("Authorization");
        if (authHeader == null) return null; 
        return authHeader.replace("Bearer ", "");
    }
    
}
```
Primeiro de tudo é realizado a validação do token, verificando se o token é válido, ou seja se ele não expirou. Após essa validação deixa acessar as rotas que necessitam de autenticação. 

## **🔒 Endpoints de Autenticação**

A API possui endpoints para autenticação e gerenciamento de usuários:

POST /auth/login - Gera um token JWT

POST /auth/register - Cria um novo usuário
