oauth2
	接口对接的场景，A厂家有一套HTTP接口需要提供给B厂家使用，由于是外网环境，所以需要有一套安全机制保障，
这个时候oauth2就可以作为一个方案

关于oauth2，其实是一个规范，本文重点讲解spring对他进行的实现

使用oauth2保护你的应用，可以分为简易的分为三个步骤

配置资源服务器
配置认证服务器
配置spring security

spring security oauth2是建立在spring security基础之上的，所以有一些体系是公用的。


环境准备
1. curl: 7.57.0 (x86_64-w64-mingw32)
2. spring-boot-version: 1.5.10.RELEASE

项目准备
1. 引入maven依赖
2. 创建资源api暴露一个商品查询接口,后续不做安全限制,一个订单查询接口,后续添加访问控制
3. 配置资源服务器和授权服务器

pom.xml
```
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.security.oauth</groupId>
	<artifactId>spring-security-oauth2</artifactId>
</dependency>
```

配置类: SecurityConfiguration
```
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter{

  @Bean
  @Override
  protected UserDetailsService userDetailsService(){
	  //将用户信息存入在内存中
      InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
      manager.createUser(User.withUsername("user_1").password("123456").authorities("USER").build());
      manager.createUser(User.withUsername("user_2").password("123456").authorities("USER").build());
      return manager;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
      // @formatter:off
      http
          .requestMatchers().anyRequest()
          .and()
              .authorizeRequests()
              .antMatchers("/oauth/*").permitAll();
      // @formatter:on
  }
}

```
配置类: OAuth2ServerConfig
```
@Configuration
public class OAuth2ServerConfig {
	 private static final String DEMO_RESOURCE_ID = "order";

	    @Configuration
	    @EnableResourceServer
	    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {
	        @Override
	        public void configure(ResourceServerSecurityConfigurer resources) {
	            resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
	        }
	        @Override
	        public void configure(HttpSecurity http) throws Exception {
	            // @formatter:off
	            http
	                    // Since we want the protected resources to be accessible in the UI as well we need
	                    // session creation to be allowed (it's disabled by default in 2.0.6)
	                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
	                    .and()
	                    .requestMatchers().anyRequest()
	                    .and()
	                    .anonymous()
	                    .and()
	                    .authorizeRequests()
	                    .antMatchers("/product/**","/order/**").authenticated();//.access("#oauth2.hasScope('select') and hasRole('ROLE_USER')")
//	                    .antMatchers("/order/**").authenticated();//配置order访问控制，必须认证过后才可以访问
	            // @formatter:on
	        }
	    }


	    @Configuration
	    @EnableAuthorizationServer
	    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	        @Autowired
	        AuthenticationManager authenticationManager;
//	        @Autowired
//	        RedisConnectionFactory redisConnectionFactory;
	        
	        
	        
	        /** <1> 配置AuthorizationServer安全认证的相关信息，创建ClientCredentialsTokenEndpointFilter  客户端身份认证核心过滤器    核心过滤器
	         * <2>ClientDetailsServiceConfigurer     配置OAuth2的客户端相关信息
	         * <3> 配置AuthorizationServerEndpointsConfigurer众多相关类，包括配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory
	         */
	        @Override
	        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
	            //配置两个客户端,一个用于password认证一个用于client认证
	            clients.inMemory().withClient("client_1")
	                    .resourceIds(DEMO_RESOURCE_ID)
	                    .authorizedGrantTypes("client_credentials", "refresh_token")
	                    .scopes("select")
	                    .authorities("client")
	                    .secret("123456")
	                    .and()
	                    .withClient("client_2")
	                    .resourceIds(DEMO_RESOURCE_ID)
	                    .authorizedGrantTypes("password", "refresh_token")
	                    .scopes("select")
	                    .authorities("client")
	                    .secret("123456");
	        }

	        @Override
	        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
	            endpoints
	                    /*.tokenStore(new RedisTokenStore(redisConnectionFactory))*/
	                    .authenticationManager(authenticationManager);
	        }

	        @Override
	        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
	            //允许表单认证
	            oauthServer.allowFormAuthenticationForClients();
	        }

	    }
}
```

启动spring boot后，会自动创建如下endpoint ::
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 Mapped "{[/oauth/authorize],methods=[POST],params=[user_oauth_approval]}" onto public org.springframework.web.servlet.View org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.approveOrDeny(java.util.Map<java.lang.String, java.lang.String>,java.util.Map<java.lang.String, ?>,org.springframework.web.bind.support.SessionStatus,java.security.Principal)
 Mapped "{[/oauth/authorize]}" onto public org.springframework.web.servlet.ModelAndView org.springframework.security.oauth2.provider.endpoint.AuthorizationEndpoint.authorize(java.util.Map<java.lang.String, java.lang.Object>,java.util.Map<java.lang.String, java.lang.String>,org.springframework.web.bind.support.SessionStatus,java.security.Principal)
 Mapped "{[/oauth/token],methods=[GET]}" onto public org.springframework.http.ResponseEntity<org.springframework.security.oauth2.common.OAuth2AccessToken> org.springframework.security.oauth2.provider.endpoint.TokenEndpoint.getAccessToken(java.security.Principal,java.util.Map<java.lang.String, java.lang.String>) throws org.springframework.web.HttpRequestMethodNotSupportedException
 Mapped "{[/oauth/token],methods=[POST]}" onto public org.springframework.http.ResponseEntity<org.springframework.security.oauth2.common.OAuth2AccessToken> org.springframework.security.oauth2.provider.endpoint.TokenEndpoint.postAccessToken(java.security.Principal,java.util.Map<java.lang.String, java.lang.String>) throws org.springframework.web.HttpRequestMethodNotSupportedException
 Mapped "{[/oauth/check_token]}" onto public java.util.Map<java.lang.String, ?> org.springframework.security.oauth2.provider.endpoint.CheckTokenEndpoint.checkToken(java.lang.String)
 Mapped "{[/oauth/confirm_access]}" onto public org.springframework.web.servlet.ModelAndView org.springframework.security.oauth2.provider.endpoint.WhitelabelApprovalEndpoint.getAccessConfirmation(java.util.Map<java.lang.String, java.lang.Object>,javax.servlet.http.HttpServletRequest) throws java.lang.Exception
 Mapped "{[/oauth/error]}" onto public org.springframework.web.servlet.ModelAndView org.springframework.security.oauth2.provider.endpoint.WhitelabelErrorEndpoint.handleError(javax.servlet.http.HttpServletRequest)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
测试结果如下：
 
访问oauth/token接口，password模式：
```
curl -X POST 'http://localhost:3130/oauth/token?username=user_1&password=123456&grant_type=password&scope=select&client_id=client_2&client_secret=123456'
```
 返回结果：
{
    "access_token": "990df2a9-fe59-40e8-8a4b-9766e756e88d",
    "token_type": "bearer",
    "refresh_token": "da067b47-b8b4-4e8e-b10a-329611f37138",
    "expires_in": 43199,
    "scope": "select"
}

直接访问资源接口
```
curl http://localhost:3130/order/1
```
返回结果：
	{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}

token不对的情况下：
```
curl http://localhost:3130/order/1?access_token=db0a6ddc-96cb-4156-9500-7b7e13b6e42d
```
返回结果：
```
{
    "error": "invalid_token",
    "error_description": "Invalid access token: db0a6ddc-96cb-4156-9500-7b7e13b6e42d"
}
```
token正确的情况下：
```
curl http://localhost:3130/order/1?access_token=990df2a9-fe59-40e8-8a4b-9766e756e88d
```
返回结果：
order id : 1 


 用POST方式访问oauth/token接口，client模式：
```
curl -X POST  'http://localhost:3130/oauth/token?grant_type=client_credentials&scope=select&client_id=client_1&client_secret=123456'
```
返回结果：
{
    "access_token": "e6b29f5d-9813-46d5-92ce-2fa89dec9392",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "select"
}



获取token,在这之前已经校验过请求的相关信息
```
package org.springframework.security.oauth2.provider.endpoint;
@FrameworkEndpoint
public class TokenEndpoint extends AbstractEndpoint {

    @RequestMapping(value = "/oauth/token", method=RequestMethod.POST)
    public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam
    Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
        ...略
        String clientId = getClientId(principal);
        ClientDetails authenticatedClient = getClientDetailsService().loadClientByClientId(clientId);//<1>
        ...略
        TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);//<2>
        ...略
        OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);//<3>
        ...略
        return getResponse(token);

    }

    private TokenGranter tokenGranter;
}
```

1. 加载客户端信息
2. 结合请求信息，创建TokenRequest
3. 将TokenRequest传递给TokenGranter颁发token


以下是生成token部分代码：
根据上面grant(tokenRequest.getGrantType(), tokenRequest);
调用：org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer
```
	private TokenGranter tokenGranter() {
		if (tokenGranter == null) {
			tokenGranter = new TokenGranter() {
				private CompositeTokenGranter delegate;

				@Override
				public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
					if (delegate == null) {
						//配置认证模式
						delegate = new CompositeTokenGranter(getDefaultTokenGranters());
					}
					return delegate.grant(grantType, tokenRequest);
				}
			};
		}
		return tokenGranter;
	}
```
认证模式配置
authorization_code	
refresh_token  ==>refresh_token 刷新token专用
implicit  ==>implicit简化模式
client_credentials


```
package org.springframework.security.oauth2.provider.ClientDetailsService;//A service that provides the details about an OAuth2 client.
public interface ClientDetailsService {
    ClientDetails loadClientByClientId(String var1) throws ClientRegistrationException;
}
```
实现接口org.springframework.security.oauth2.provider.client.InMemoryClientDetailsService
	重写loadClientByClientId方法
当前是client模式继续调用：	org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter extends AbstractTokenGranter
	这个类继承org.springframework.security.oauth2.provider.token.AbstractTokenGranter，重写了grant()方法
	
	
```	
package org.springframework.security.oauth2.provider.client;
public class ClientCredentialsTokenGranter extends AbstractTokenGranter {
	...省略其它代码
	@Override
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
		OAuth2AccessToken token = super.grant(grantType, tokenRequest);
		if (token != null) {
			DefaultOAuth2AccessToken norefresh = new DefaultOAuth2AccessToken(token);
			// The spec says that client credentials should not be allowed to get a refresh token
			if (!allowRefresh) {
				norefresh.setRefreshToken(null);
			}
			token = norefresh;
		}
		return token;//返回结果：token {value=dad46648-1820-4203-a71c-4d42201c9f3f,expiration= Wed Feb 07 23:04:23 CST 2018,tokenType=bearer}
	}
}
```

重写grant()
```
package org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
public abstract class AbstractTokenGranter implements TokenGranter {
	...省略其它代码
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
		//判断当前认证模式
		if (!this.grantType.equals(grantType)) {
			return null;
		}
		//获取传进来的clientId
		String clientId = tokenRequest.getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, client);
		
		logger.debug("Getting access token for: " + clientId);

		return getAccessToken(client, tokenRequest);
	}
	
	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
		//tokenServices来自接口org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices tokenServices;
		return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest));
	}
	...省略其它代码

}
```



DefaultTokenServices 继承了AuthorizationServerTokenServices接口 如下：

AuthorizationServerTokenServices 的作用，
1. 创建token
2. 刷新token
3. 获取token的实现
在创建token时，他会调用tokenStore对产生的token和相关信息存储到对应的实现类中

```
package org.springframework.security.oauth2.provider.token.DefaultTokenServices;
public class DefaultTokenServices implements AuthorizationServerTokenServices, ResourceServerTokenServices,ConsumerTokenServices, InitializingBean {
		private int refreshTokenValiditySeconds = 60 * 60 * 24 * 30; // default 30 days.

		private int accessTokenValiditySeconds = 60 * 60 * 12; // default 12 hours.授权是12个小时
		
		private TokenStore tokenStore;//这里使用是内存模式，调用的InMemoryTokenStore类的实现方法
		...
		
		
	//初次生成token方法
	@Transactional
	public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {
	//是否已存在token
		OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
		
		OAuth2RefreshToken refreshToken = null;
		if (existingAccessToken != null) {
			if (existingAccessToken.isExpired()) {//是否过期 Wed Feb 07 23:04:23 CST 2018
				if (existingAccessToken.getRefreshToken() != null) {
					refreshToken = existingAccessToken.getRefreshToken();
					// The token store could remove the refresh token when the
					// access token is removed, but we want to
					// be sure...
					tokenStore.removeRefreshToken(refreshToken);
				}
				tokenStore.removeAccessToken(existingAccessToken);
			}
			else {
				// Re-store the access token in case the authentication has changed
				tokenStore.storeAccessToken(existingAccessToken, authentication);
				return existingAccessToken;
			}
		}

		// Only create a new refresh token if there wasn't an existing one
		// associated with an expired access token.
		// Clients might be holding existing refresh tokens, so we re-use it in
		// the case that the old access token
		// expired.
		
		if (refreshToken == null) {
			refreshToken = createRefreshToken(authentication);//直接
		}
		// But the refresh token itself might need to be re-issued if it has
		// expired.
		else if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
			ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
			if (System.currentTimeMillis() > expiring.getExpiration().getTime()) {
				refreshToken = createRefreshToken(authentication);
			}
		}
//调用下面的createAccessToken方法 返回结果：dad46648-1820-4203-a71c-4d42201c9f3f
		OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
		
		tokenStore.storeAccessToken(accessToken, authentication);//调用底下InMemoryTokenStore storeAccessToken() 本文54行
		// In case it was modified
		refreshToken = accessToken.getRefreshToken();
		if (refreshToken != null) {
			tokenStore.storeRefreshToken(refreshToken, authentication);
		}
		return accessToken;

	}
	//参数说明：authentication放是请求的信息，如id，过期时间，refreshToken = cac4c9aa-0d4d-4295-bb9a-8a770d218a85 ，就是刚才createRefreshToken中获取的uuid
	private OAuth2AccessToken createAccessToken(OAuth2Authentication authentication, OAuth2RefreshToken refreshToken) {
		DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());//生的token值 ：dad46648-1820-4203-a71c-4d42201c9f3f
		int validitySeconds = getAccessTokenValiditySeconds(authentication.getOAuth2Request());//43200
		if (validitySeconds > 0) {
			token.setExpiration(new Date(System.currentTimeMillis() + (validitySeconds * 1000L)));//为token设置过期时间：Wed Feb 07 23:04:23 CST 2018
		}
		token.setRefreshToken(refreshToken);
		token.setScope(authentication.getOAuth2Request().getScope());

		return accessTokenEnhancer != null ? accessTokenEnhancer.enhance(token, authentication) : token;
	}
	
	private OAuth2RefreshToken createRefreshToken(OAuth2Authentication authentication) {
		if (!isSupportRefreshToken(authentication.getOAuth2Request())) {
			return null;
		}
		int validitySeconds = getRefreshTokenValiditySeconds(authentication.getOAuth2Request());//调用下面方法return 2592000
		String value = UUID.randomUUID().toString();//获取UUID cac4c9aa-0d4d-4295-bb9a-8a770d218a85
		if (validitySeconds > 0) {
			return new DefaultExpiringOAuth2RefreshToken(value, new Date(System.currentTimeMillis()
					+ (validitySeconds * 1000L)));//设置有效期
			//这个类继承自：public class DefaultExpiringOAuth2RefreshToken extends DefaultOAuth2RefreshToken implements ExpiringOAuth2RefreshToken {}		
		}
		return new DefaultOAuth2RefreshToken(value);
	}
	
	protected boolean isSupportRefreshToken(OAuth2Request clientAuth) {
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
			return client.getAuthorizedGrantTypes().contains("refresh_token");
		}
		return this.supportRefreshToken;// 返回结果：@return boolean to indicate if refresh token is supported
	}
	
	//The refresh token validity period in seconds 刷新令牌有效期
	protected int getRefreshTokenValiditySeconds(OAuth2Request clientAuth) {
		if (clientDetailsService != null) {
			ClientDetails client = clientDetailsService.loadClientByClientId(clientAuth.getClientId());
			Integer validity = client.getRefreshTokenValiditySeconds();
			if (validity != null) {
				return validity;
			}
		}
		return refreshTokenValiditySeconds;//return 2592000
	}	
	
	
	public OAuth2Authentication loadAuthentication(String accessTokenValue) throws AuthenticationException,
			InvalidTokenException {
		OAuth2AccessToken accessToken = tokenStore.readAccessToken(accessTokenValue);
		if (accessToken == null) {
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		else if (accessToken.isExpired()) {
			tokenStore.removeAccessToken(accessToken);
			throw new InvalidTokenException("Access token expired: " + accessTokenValue);
		}

		OAuth2Authentication result = tokenStore.readAuthentication(accessToken);
		if (result == null) {
			// in case of race condition
			throw new InvalidTokenException("Invalid access token: " + accessTokenValue);
		}
		if (clientDetailsService != null) {
			String clientId = result.getOAuth2Request().getClientId();
			try {
				clientDetailsService.loadClientByClientId(clientId);
			}
			catch (ClientRegistrationException e) {
				throw new InvalidTokenException("Client not valid: " + clientId, e);
			}
		}
		return result;
	}
	
	
	...
}
```
	

接口 org.springframework.security.oauth2.provider.token.TokenStore tokenStore;
TokenStore定义以下几种方式扩展token
1. redis
2. jwk
3. jws
4. inMemory
5. jdbc
	
当前使用内存模式:
//实例化一个generator
//第一次 authenticationToAccessTokenStore的map为空{}
//第二次进来 {9be883e636cfea77f815d24f8aece0c4=dad46648-1820-4203-a71c-4d42201c9f3f}
//accessToken不为空，并且通过authorizationRequest.getClientId() 与 authentication.getName() 验证key的一致性


```
package org.springframework.security.oauth2.provider.token.store;
public class InMemoryTokenStore implements TokenStore {
	...
	//实例化一个generator
	private AuthenticationKeyGenerator authenticationKeyGenerator = new DefaultAuthenticationKeyGenerator();
	private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();
	
	public OAuth2AccessToken getAccessToken(OAuth2Authentication authentication) {
	
		String key = authenticationKeyGenerator.extractKey(authentication);
		
		//第一次 authenticationToAccessTokenStore的map为空{}
		//第二次进来 {9be883e636cfea77f815d24f8aece0c4=dad46648-1820-4203-a71c-4d42201c9f3f}
		
		OAuth2AccessToken accessToken = authenticationToAccessTokenStore.get(key);
		
		//accessToken不为空，并且通过authorizationRequest.getClientId() 与 authentication.getName() 验证key的一致性
		if (accessToken != null
				&& !key.equals(authenticationKeyGenerator.extractKey(readAuthentication(accessToken.getValue())))) {
			// Keep the stores consistent (maybe the same user is represented by this authentication but the details
			// have changed)
			storeAccessToken(accessToken, authentication);
		}
		return accessToken;//这里直接返回一个空的tonken
	}	
	
	...
	
	private final ConcurrentHashMap<String, OAuth2AccessToken> accessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	private final ConcurrentHashMap<String, OAuth2Authentication> authenticationStore = new ConcurrentHashMap<String, OAuth2Authentication>();

	private final ConcurrentHashMap<String, OAuth2AccessToken> authenticationToAccessTokenStore = new ConcurrentHashMap<String, OAuth2AccessToken>();

	private final DelayQueue<TokenExpiry> expiryQueue = new DelayQueue<TokenExpiry>();//过期队列

	private final ConcurrentHashMap<String, TokenExpiry> expiryMap = new ConcurrentHashMap<String, TokenExpiry>();//判断过期

	//后者是token {cac4c9aa-0d4d-4295-bb9a-8a770d218a85 = dad46648-1820-4203-a71c-4d42201c9f3f}
	private final ConcurrentHashMap<String, String> refreshTokenToAccessTokenStore = new ConcurrentHashMap<String, String>();


	public void storeAccessToken(OAuth2AccessToken token, OAuth2Authentication authentication) {
		if (this.flushCounter.incrementAndGet() >= this.flushInterval) {
			flush();
			this.flushCounter.set(0);
		}
		this.accessTokenStore.put(token.getValue(), token);
		this.authenticationStore.put(token.getValue(), authentication);
		this.authenticationToAccessTokenStore.put(authenticationKeyGenerator.extractKey(authentication), token);
		if (!authentication.isClientOnly()) {
			addToCollection(this.userNameToAccessTokenStore, getApprovalKey(authentication), token);
		}
		
		
		//clientIdToAccessTokenStore = {client_1=[dad46648-1820-4203-a71c-4d42201c9f3f]}
		//authentication.getOAuth2Request().getClientId() = client_1
		//token = dad46648-1820-4203-a71c-4d42201c9f3f
		addToCollection(this.clientIdToAccessTokenStore, authentication.getOAuth2Request().getClientId(), token);
		
		
		if (token.getExpiration() != null) {
			TokenExpiry expiry = new TokenExpiry(token.getValue(), token.getExpiration());
			// Remove existing expiry for this token if present
			expiryQueue.remove(expiryMap.put(token.getValue(), expiry));
			this.expiryQueue.put(expiry);
		}
		if (token.getRefreshToken() != null && token.getRefreshToken().getValue() != null) {
			this.refreshTokenToAccessTokenStore.put(token.getRefreshToken().getValue(), token.getValue());
			this.accessTokenToRefreshTokenStore.put(token.getValue(), token.getRefreshToken().getValue());
		}
	}

	public OAuth2Authentication readAuthentication(OAuth2AccessToken token) {//获取已经存在的token
		return readAuthentication(token.getValue());
	}

}
```
	
以上authenticationKeyGenerator 来自:

传参信息,就是方法中的authentication对象信息
authentication对象存了storedRequest对象，具体信息有：
	requestParameters = {grant_type=client_credentials, client_id=client_1, scope=select}
	resourceIds = [order];
	scope = [select];
	refresh = null;
	clientId = client_1;
	extensions = {};为空
	approved = true;
	authorities = [client];
	responeseType = [];

传参信息：values = {client_id=client_1, scope=select}

调用 MessageDigest  用MD5生成

```
package org.springframework.security.oauth2.provider.token.DefaultAuthenticationKeyGenerator;
public class DefaultAuthenticationKeyGenerator implements AuthenticationKeyGenerator {
....
//传参信息,就是方法中的authentication对象信息

//org.springframework.security.oauth2.provider.OAuth2Authentication@c5b7c21b: 
//Principal: client_1; Credentials: [PROTECTED]; Authenticated: true; Details: null; Granted Authorities: client

	public String extractKey(OAuth2Authentication authentication) {
		Map<String, String> values = new LinkedHashMap<String, String>();
		OAuth2Request authorizationRequest = authentication.getOAuth2Request();
		//authentication对象存了storedRequest对象，具体信息有：
		//	requestParameters = {grant_type=client_credentials, client_id=client_1, scope=select}
		//	resourceIds = [order];
		//	scope = [select];
		//	refresh = null;
		//	clientId = client_1;
		//	extensions = {};为空
		//	approved = true;
		//	authorities = [client];
		//	responeseType = [];
			
		if (!authentication.isClientOnly()) {
			values.put(USERNAME, authentication.getName());
		}
		values.put(CLIENT_ID, authorizationRequest.getClientId());
		if (authorizationRequest.getScope() != null) {
			values.put(SCOPE, OAuth2Utils.formatParameterList(new TreeSet<String>(authorizationRequest.getScope())));
		}
		return generateKey(values);//传参信息：values = {client_id=client_1, scope=select}
	}



	protected String generateKey(Map<String, String> values) {
		MessageDigest digest;
		try {
			digest = MessageDigest.getInstance("MD5");
			byte[] bytes = digest.digest(values.toString().getBytes("UTF-8"));
			//value就是上面的参数
			//bytes =  [-101, -24, -125, -26, 54, -49, -22, 119, -8, 21, -46, 79, -118, -20, -32, -60]
			return String.format("%032x", new BigInteger(1, bytes));  //返回的参数为  9be883e636cfea77f815d24f8aece0c4
		} catch (NoSuchAlgorithmException nsae) {
			throw new IllegalStateException("MD5 algorithm not available.  Fatal (should be in the JDK).", nsae);
		} catch (UnsupportedEncodingException uee) {
			throw new IllegalStateException("UTF-8 encoding not available.  Fatal (should be in the JDK).", uee);
		}
	}

}
```
	
这里用的是java.security.MessageDigest
```
public abstract class MessageDigest extends MessageDigestSpi {
    public void update(byte[] input) {
        engineUpdate(input, 0, input.length);
        state = IN_PROGRESS;
    }
	
	public byte[] digest(byte[] input) {//调用当前方法
        update(input);
        return digest();
    }
	public byte[] digest() {
        /* Resetting is the responsibility of implementors. */
        byte[] result = engineDigest();
        state = INITIAL;
        return result;
    }
}
```
生成md5的值

```
public abstract class MessageDigestSpi {

	...省略其它代码
    protected void engineUpdate(ByteBuffer input) {
        if (input.hasRemaining() == false) {
            return;
        }
        if (input.hasArray()) {
            byte[] b = input.array();
            int ofs = input.arrayOffset();
            int pos = input.position();
            int lim = input.limit();
            engineUpdate(b, ofs + pos, lim - pos);
            input.position(lim);
        } else {
            int len = input.remaining();
            int n = JCAUtil.getTempArraySize(len);
            if ((tempArray == null) || (n > tempArray.length)) {
                tempArray = new byte[n];
            }
            while (len > 0) {
                int chunk = Math.min(len, tempArray.length);
                input.get(tempArray, 0, chunk);
                engineUpdate(tempArray, 0, chunk);
                len -= chunk;
            }
        }
    }
	...省略其它代码
	
}
```
原子锁
```
public class AtomicInteger extends Number implements java.io.Serializable {

	...省略其它代码
	
	/**
		* Atomically increments by one the current value.
		*
		* @return the updated value
		*/
	public final int incrementAndGet() {
		return unsafe.getAndAddInt(this, valueOffset, 1) + 1;
	}
	
	...省略其它代码
	
}
```
把集合格式化为str
```
/** coll 要转换的集成
*	delim =" ";
*	prefix = "";
*	suffix = "";	
*/
public static String collectionToDelimitedString(Collection<?> coll, String delim, String prefix, String suffix) {
	if (CollectionUtils.isEmpty(coll)) {
		return "";
	}

	StringBuilder sb = new StringBuilder();
	Iterator<?> it = coll.iterator();
	while (it.hasNext()) {
		sb.append(prefix).append(it.next()).append(suffix);
		if (it.hasNext()) {
			sb.append(delim);
		}
	}
	return sb.toString();
}	
```
	
	

发送请求时 http://localhost:3130/order/1 （加上access_token此请求不被拦截）
	

经过filter
```
package org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationProcessingFilter;
public class OAuth2AuthenticationProcessingFilter implements Filter, InitializingBean {

	private TokenExtractor tokenExtractor = new BearerTokenExtractor();
	
	//核心过滤方法
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {

		final boolean debug = logger.isDebugEnabled();
		final HttpServletRequest request = (HttpServletRequest) req;
		final HttpServletResponse response = (HttpServletResponse) res;

		try {

			Authentication authentication = tokenExtractor.extract(request);
			
			if (authentication == null) {
				if (stateless && isAuthenticated()) {
					if (debug) {
						logger.debug("Clearing security context.");
					}
					SecurityContextHolder.clearContext();
				}
				if (debug) {
					logger.debug("No token in request, will continue chain.");
				}
			}
			else {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, authentication.getPrincipal());
				if (authentication instanceof AbstractAuthenticationToken) {
					AbstractAuthenticationToken needsDetails = (AbstractAuthenticationToken) authentication;
					needsDetails.setDetails(authenticationDetailsSource.buildDetails(request));
				}
				Authentication authResult = authenticationManager.authenticate(authentication);///////////////验证身份

				if (debug) {
					logger.debug("Authentication success: " + authResult);
				}

				eventPublisher.publishAuthenticationSuccess(authResult);
				SecurityContextHolder.getContext().setAuthentication(authResult);///？？？？？？

			}
		}
		catch (OAuth2Exception failed) {
			SecurityContextHolder.clearContext();

			if (debug) {
				logger.debug("Authentication request failed: " + failed);
			}
			eventPublisher.publishAuthenticationFailure(new BadCredentialsException(failed.getMessage(), failed),
					new PreAuthenticatedAuthenticationToken("access-token", "N/A"));

			authenticationEntryPoint.commence(request, response,
					new InsufficientAuthenticationException(failed.getMessage(), failed));

			return;
		}

		chain.doFilter(request, response);
	}
}
```
	
	
进入BearerTokenExtractor  extractToken 方法	
```
package org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor;
public class BearerTokenExtractor implements TokenExtractor {

	protected String extractToken(HttpServletRequest request) {
		// first check the header...
		String token = extractHeaderToken(request);//通过header 获取token

		// bearer type allows a request parameter as well
		if (token == null) {
			logger.debug("Token not found in headers. Trying request parameters.");
			token = request.getParameter(OAuth2AccessToken.ACCESS_TOKEN);//通问get传参的方式获取token
			if (token == null) {
				logger.debug("Token not found in request parameters.  Not an OAuth2 request.");
			}
			else {
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE, OAuth2AccessToken.BEARER_TYPE);
			}
		}

		return token;
	}
	/**
	 * Extract the OAuth bearer token from a header.
	 * 
	 * @param request The request.
	 * @return The token, or null if no OAuth authorization header was supplied.
	 */
	protected String extractHeaderToken(HttpServletRequest request) {
		Enumeration<String> headers = request.getHeaders("Authorization");
			/**
			=== MimeHeaders ===
			cache-control = no-cache
			postman-token = 6b02c49d-876d-4b5f-91a5-e5067211804e
			user-agent = PostmanRuntime/7.1.1
			accept = */*
			host = localhost:3130
			cookie = JSESSIONID=165059F4F2B7110F98E34A1C8AC40842
			accept-encoding = gzip, deflate
			connection = keep-alive
			*/
		
		
		while (headers.hasMoreElements()) { // typically there is only one (most servers enforce that)
			String value = headers.nextElement();
			if ((value.toLowerCase().startsWith(OAuth2AccessToken.BEARER_TYPE.toLowerCase()))) {
				String authHeaderValue = value.substring(OAuth2AccessToken.BEARER_TYPE.length()).trim();
				// Add this here for the auth details later. Would be better to change the signature of this method.
				request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_TYPE,
						value.substring(0, OAuth2AccessToken.BEARER_TYPE.length()).trim());
				int commaIndex = authHeaderValue.indexOf(',');
				if (commaIndex > 0) {
					authHeaderValue = authHeaderValue.substring(0, commaIndex);
				}
				return authHeaderValue;
			}
		}

		return null;
	}

}
```
验证身份类 ：
```
package org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationManager;
public class OAuth2AuthenticationManager implements AuthenticationManager, InitializingBean {
	...
	private ResourceServerTokenServices tokenServices;
	
	
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		if (authentication == null) {
			throw new InvalidTokenException("Invalid token (token not found)");
		}
		String token = (String) authentication.getPrincipal();
		OAuth2Authentication auth = tokenServices.loadAuthentication(token);
		if (auth == null) {
			throw new InvalidTokenException("Invalid token: " + token);
		}

		Collection<String> resourceIds = auth.getOAuth2Request().getResourceIds();
		if (resourceId != null && resourceIds != null && !resourceIds.isEmpty() && !resourceIds.contains(resourceId)) {
			throw new OAuth2AccessDeniedException("Invalid token does not contain resource id (" + resourceId + ")");
		}

		checkClientDetails(auth);

		if (authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
			OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
			// Guard against a cached copy of the same details
			if (!details.equals(auth.getDetails())) {
				// Preserve the authentication details from the one loaded by token services
				details.setDecodedDetails(auth.getDetails());
			}
		}
		auth.setDetails(authentication.getDetails());
		auth.setAuthenticated(true);
		return auth;

	}
	...
}
```



