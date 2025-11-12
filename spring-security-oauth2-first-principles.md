# Building Spring Security & OAuth2 from First Principles

## 🎯 A Journey from Zero to Hero

> **The Goal**: Understand Spring Security and OAuth2 by building them from scratch, focusing on the *why* behind every decision.

---

## Table of Contents

1. [The Problem: Why Do We Need Security?](#part-1-the-problem)
2. [Building Authentication from Scratch](#part-2-building-authentication)
3. [The Authorization Challenge](#part-3-authorization)
4. [The Delegation Problem](#part-4-delegation)
5. [Inventing OAuth2](#part-5-inventing-oauth2)
6. [Spring Security: The Framework](#part-6-spring-security)
7. [Practical Implementation Guide](#part-7-practical-guide)

---

# Part 1: The Problem

## 🤔 Why Do We Need Security?

Imagine you're building a simple blog application. Users can:
- Write posts
- Read posts
- Edit their posts
- Delete their posts

### Version 1: No Security

```java
@RestController
public class BlogController {

    @PostMapping("/posts")
    public Post createPost(@RequestBody Post post) {
        return postRepository.save(post);
    }

    @DeleteMapping("/posts/{id}")
    public void deletePost(@PathVariable Long id) {
        postRepository.deleteById(id);
    }
}
```

### ❌ The Problems

1. **Anyone can create posts** pretending to be anyone
2. **Anyone can delete anyone's posts**
3. **No way to know who did what**
4. **Can't have private posts**

### 💡 The Realization

> **We need to answer two questions:**
> 1. **Who are you?** (Authentication)
> 2. **What can you do?** (Authorization)

Let's solve these problems step by step.

---

# Part 2: Building Authentication

## 🔑 Version 2: The Password Solution

### The Idea
"Each user provides credentials to prove their identity."

```java
@RestController
public class BlogController {

    @PostMapping("/posts")
    public Post createPost(
        @RequestParam String username,
        @RequestParam String password,
        @RequestBody Post post
    ) {
        // Check credentials on EVERY request
        User user = userRepository.findByUsername(username);

        if (user == null || !user.getPassword().equals(password)) {
            throw new UnauthorizedException("Invalid credentials");
        }

        post.setAuthor(user);
        return postRepository.save(post);
    }
}
```

### ❌ Problems with This Approach

| Problem | Impact |
|---------|--------|
| **Credentials in every request** | Password exposed in logs, network traffic |
| **No password hashing** | Database breach = all passwords exposed |
| **Checking auth in every method** | Code duplication, easy to forget |
| **Tight coupling** | Business logic mixed with security |

### 💡 The Insight

> **Authentication should be:**
> 1. **Centralized** - check once, not in every method
> 2. **Stateful** - remember who you are after login
> 3. **Secure** - never expose raw passwords

---

## 🍪 Version 3: Sessions & Cookies

### The Idea
"Check credentials once, then remember the user."

```java
// Step 1: Login endpoint
@PostMapping("/login")
public void login(
    @RequestParam String username,
    @RequestParam String password,
    HttpSession session
) {
    User user = userRepository.findByUsername(username);

    if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
        throw new UnauthorizedException("Invalid credentials");
    }

    // Store user in session
    session.setAttribute("user", user);
}

// Step 2: Extract user from session
@PostMapping("/posts")
public Post createPost(
    @RequestBody Post post,
    HttpSession session
) {
    User user = (User) session.getAttribute("user");

    if (user == null) {
        throw new UnauthorizedException("Not logged in");
    }

    post.setAuthor(user);
    return postRepository.save(post);
}
```

### ✅ Better! But Still Problems...

| Problem | Why It Matters |
|---------|----------------|
| **Still checking in every method** | Code duplication |
| **Session stored on server** | Doesn't scale (load balancer issues) |
| **No standard format** | Each app reinvents the wheel |

### 💡 The Next Insight

> **We need a way to:**
> 1. **Intercept requests** before they reach our controllers
> 2. **Extract and validate** authentication
> 3. **Make user info available** to all methods
> 4. **Do this automatically** without changing our business logic

---

## 🔒 Version 4: The Filter Chain Pattern

### The Idea
"Create a chain of filters that process requests before controllers."

```
Request → Filter 1 → Filter 2 → Filter 3 → Controller
                ↓         ↓         ↓
             [Auth]   [Logging]  [CSRF]
```

### Implementation

```java
// 1. Security Filter
public class SecurityFilter implements Filter {

    @Override
    public void doFilter(
        ServletRequest request,
        ServletResponse response,
        FilterChain chain
    ) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpSession session = httpRequest.getSession(false);

        // Extract user from session
        User user = null;
        if (session != null) {
            user = (User) session.getAttribute("user");
        }

        if (user != null) {
            // Store user in thread-local for access in controllers
            SecurityContext.setCurrentUser(user);
        }

        try {
            // Continue to next filter or controller
            chain.doFilter(request, response);
        } finally {
            // Clean up thread-local
            SecurityContext.clear();
        }
    }
}

// 2. Security Context (Thread-Local Storage)
public class SecurityContext {
    private static ThreadLocal<User> currentUser = new ThreadLocal<>();

    public static void setCurrentUser(User user) {
        currentUser.set(user);
    }

    public static User getCurrentUser() {
        return currentUser.get();
    }

    public static void clear() {
        currentUser.remove();
    }
}

// 3. Now our controller is clean!
@PostMapping("/posts")
public Post createPost(@RequestBody Post post) {
    User user = SecurityContext.getCurrentUser();

    if (user == null) {
        throw new UnauthorizedException("Not logged in");
    }

    post.setAuthor(user);
    return postRepository.save(post);
}
```

### ✅ Much Better!

**Benefits:**
- ✅ Centralized authentication logic
- ✅ Separation of concerns
- ✅ Easy to add more security filters
- ✅ Controllers focus on business logic

### ❌ Still Missing...

- What about different authentication methods? (Basic Auth, JWT, API Keys)
- How to configure which URLs need authentication?
- What about authorization (roles, permissions)?

---

## 🎨 Version 5: The Strategy Pattern

### The Idea
"Support multiple authentication methods with a common interface."

```java
// 1. Authentication interface
public interface AuthenticationProvider {
    User authenticate(HttpServletRequest request);
    boolean supports(HttpServletRequest request);
}

// 2. Session-based authentication
public class SessionAuthenticationProvider implements AuthenticationProvider {

    @Override
    public User authenticate(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session != null) {
            return (User) session.getAttribute("user");
        }
        return null;
    }

    @Override
    public boolean supports(HttpServletRequest request) {
        return request.getSession(false) != null;
    }
}

// 3. JWT authentication
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public User authenticate(HttpServletRequest request) {
        String token = extractToken(request);
        if (token != null) {
            return jwtService.validateAndExtractUser(token);
        }
        return null;
    }

    @Override
    public boolean supports(HttpServletRequest request) {
        return extractToken(request) != null;
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
}

// 4. Updated Security Filter
public class SecurityFilter implements Filter {

    private List<AuthenticationProvider> providers;

    @Override
    public void doFilter(
        ServletRequest request,
        ServletResponse response,
        FilterChain chain
    ) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // Try each provider
        User user = null;
        for (AuthenticationProvider provider : providers) {
            if (provider.supports(httpRequest)) {
                user = provider.authenticate(httpRequest);
                if (user != null) break;
            }
        }

        if (user != null) {
            SecurityContext.setCurrentUser(user);
        }

        try {
            chain.doFilter(request, response);
        } finally {
            SecurityContext.clear();
        }
    }
}
```

### 🎉 Now We Have:

1. **Pluggable authentication** - easy to add new methods
2. **Clean separation** - each provider handles one method
3. **Flexible** - multiple methods can coexist

---

# Part 3: Authorization

## 🚦 The Authorization Challenge

Authentication answers "Who are you?"
Authorization answers "What can you do?"

### The Scenario

Your blog now has:
- **Regular users** - can create/edit/delete their own posts
- **Moderators** - can delete any post, ban users
- **Admins** - can do everything

### ❌ Version 1: Hard-coded Checks

```java
@DeleteMapping("/posts/{id}")
public void deletePost(@PathVariable Long id) {
    User currentUser = SecurityContext.getCurrentUser();
    Post post = postRepository.findById(id);

    // Hard-coded authorization
    if (!post.getAuthor().equals(currentUser) &&
        !currentUser.getRole().equals("ADMIN") &&
        !currentUser.getRole().equals("MODERATOR")) {
        throw new ForbiddenException("Cannot delete this post");
    }

    postRepository.deleteById(id);
}

@DeleteMapping("/users/{id}/ban")
public void banUser(@PathVariable Long id) {
    User currentUser = SecurityContext.getCurrentUser();

    // More hard-coded checks
    if (!currentUser.getRole().equals("ADMIN") &&
        !currentUser.getRole().equals("MODERATOR")) {
        throw new ForbiddenException("Cannot ban users");
    }

    userService.ban(id);
}
```

### ❌ Problems

- Authorization logic scattered everywhere
- Hard to change permissions
- Code duplication
- Easy to forget checks
- Can't unit test easily

---

## 🎯 Version 2: Role-Based Access Control (RBAC)

### The Idea
"Define what each role can do, check roles not specific logic."

```java
// 1. Define roles and permissions
public enum Role {
    USER,
    MODERATOR,
    ADMIN
}

// 2. Annotation-based authorization
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RequireRole {
    Role[] value();
}

// 3. Authorization filter
public class AuthorizationFilter implements Filter {

    @Override
    public void doFilter(
        ServletRequest request,
        ServletResponse response,
        FilterChain chain
    ) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        // Get the method being called
        Method method = getTargetMethod(httpRequest);

        // Check if method requires roles
        RequireRole annotation = method.getAnnotation(RequireRole.class);

        if (annotation != null) {
            User user = SecurityContext.getCurrentUser();

            if (user == null) {
                sendError(response, 401, "Not authenticated");
                return;
            }

            Role[] requiredRoles = annotation.value();
            if (!hasAnyRole(user, requiredRoles)) {
                sendError(response, 403, "Forbidden");
                return;
            }
        }

        chain.doFilter(request, response);
    }

    private boolean hasAnyRole(User user, Role[] roles) {
        for (Role role : roles) {
            if (user.getRole() == role) {
                return true;
            }
        }
        return false;
    }
}

// 4. Clean controller code!
@DeleteMapping("/users/{id}/ban")
@RequireRole({Role.ADMIN, Role.MODERATOR})
public void banUser(@PathVariable Long id) {
    // Just business logic, no authorization checks
    userService.ban(id);
}

@DeleteMapping("/posts/{id}")
@RequireRole({Role.USER, Role.ADMIN, Role.MODERATOR})
public void deletePost(@PathVariable Long id) {
    User currentUser = SecurityContext.getCurrentUser();
    Post post = postRepository.findById(id);

    // Resource-specific check
    if (!post.getAuthor().equals(currentUser) &&
        !hasRole(currentUser, Role.ADMIN, Role.MODERATOR)) {
        throw new ForbiddenException();
    }

    postRepository.deleteById(id);
}
```

### ✅ Better! But...

What about more complex rules?
- "Users can edit their own posts"
- "Users can view posts in groups they belong to"
- "Users can approve posts if they're a moderator of that category"

### 💡 The Insight

> **We need:**
> 1. **Role-based** checks for simple cases
> 2. **Resource-based** checks for complex cases
> 3. **Expression language** for flexible rules
> 4. **Centralized configuration** for managing rules

---

## 🎭 Version 3: Expression-Based Authorization

### The Idea
"Use expressions to define complex authorization rules."

```java
// 1. Expression annotation
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface PreAuthorize {
    String value(); // Expression to evaluate
}

// 2. Expression evaluator
public class SecurityExpressionEvaluator {

    public boolean evaluate(String expression, SecurityContext context) {
        // Parse and evaluate expression
        // Example expressions:
        // - "hasRole('ADMIN')"
        // - "hasRole('USER') and isOwner(#postId)"
        // - "hasPermission(#postId, 'POST', 'DELETE')"

        return expressionParser.parse(expression).evaluate(context);
    }
}

// 3. Use in controllers
@DeleteMapping("/posts/{id}")
@PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and isOwner(#id))")
public void deletePost(@PathVariable Long id) {
    postRepository.deleteById(id);
}

@GetMapping("/posts/{id}")
@PreAuthorize("isPublic(#id) or hasPermission(#id, 'POST', 'READ')")
public Post getPost(@PathVariable Long id) {
    return postRepository.findById(id);
}
```

### 🎉 Now We Have:

1. **Flexible authorization** - express any rule
2. **Declarative** - rules visible at method level
3. **Reusable** - define helper methods (isOwner, hasPermission)
4. **Testable** - expressions can be tested independently

---

# Part 4: The Delegation Problem

## 🤝 A New Challenge: Third-Party Access

### The Scenario

Your blog is popular! Now you want:
- **Mobile app** - users login via app
- **Analytics service** - reads post data
- **Publishing service** - cross-posts to other platforms
- **Editor app** - third-party writing tool

### ❌ The Naive Approach: Share Passwords

```
User: "Dear Analytics Service,
       here's my username and password,
       please read my posts."
```

### 😱 Why This Is Terrible

| Problem | Impact |
|---------|--------|
| **Full access** | Service can delete posts, change password |
| **No revocation** | Must change password to revoke access |
| **No scope limit** | Can't give "read-only" access |
| **Trust issues** | Third party stores your password |
| **No audit trail** | Can't tell what service did what |

### 💡 The Insight

> **We need a way to:**
> 1. **Delegate access** without sharing passwords
> 2. **Limit scope** (read-only, write-only, specific resources)
> 3. **Time-limited** access (expires automatically)
> 4. **Revocable** access (without changing password)
> 5. **Auditable** (know what happened when)

This is the problem **OAuth2** solves!

---

# Part 5: Inventing OAuth2

## 🎫 Version 1: Access Tokens

### The Idea
"Issue temporary tokens instead of sharing passwords."

```java
// 1. Token model
public class AccessToken {
    private String token;
    private User user;
    private Instant expiresAt;
    private Set<String> scopes; // What can this token do?
}

// 2. Token generation endpoint
@PostMapping("/token")
public TokenResponse createToken(
    @RequestParam String username,
    @RequestParam String password,
    @RequestParam Set<String> scopes
) {
    // Verify credentials
    User user = authenticate(username, password);

    // Generate token
    AccessToken token = new AccessToken();
    token.setToken(UUID.randomUUID().toString());
    token.setUser(user);
    token.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));
    token.setScopes(scopes);

    tokenRepository.save(token);

    return new TokenResponse(token.getToken(), token.getExpiresAt());
}

// 3. Token authentication provider
public class TokenAuthenticationProvider implements AuthenticationProvider {

    @Override
    public User authenticate(HttpServletRequest request) {
        String tokenString = extractToken(request);

        if (tokenString != null) {
            AccessToken token = tokenRepository.findByToken(tokenString);

            if (token != null && token.getExpiresAt().isAfter(Instant.now())) {
                return token.getUser();
            }
        }

        return null;
    }
}

// 4. Scope-based authorization
@GetMapping("/posts")
@RequireScope("posts:read")
public List<Post> getPosts() {
    return postRepository.findAll();
}

@PostMapping("/posts")
@RequireScope("posts:write")
public Post createPost(@RequestBody Post post) {
    return postRepository.save(post);
}
```

### ✅ Better!

- ✅ No password sharing
- ✅ Scoped access
- ✅ Time-limited
- ✅ Revocable

### ❌ But Still a Problem...

The third-party app still needs to collect your username and password!

```
Mobile App: "Please enter your blog username and password"
User: "Here's my password..." 😟
```

The user must **trust** the mobile app not to store the password.

---

## 🔄 Version 2: The Authorization Code Flow

### The Idea
"Never give passwords to third parties. Use a redirect flow."

### The Flow

```
1. User clicks "Connect to Blog" in Mobile App

2. Mobile App redirects to Blog website:
   https://blog.com/authorize?
     client_id=mobile-app
     &redirect_uri=app://callback
     &scope=posts:read posts:write
     &response_type=code

3. User logs in on BLOG website (not Mobile App!)
   User sees: "Mobile App wants to:
               - Read your posts
               - Write new posts
               Do you approve?"

4. User clicks "Approve"

5. Blog redirects back to Mobile App:
   app://callback?code=xyz789

6. Mobile App exchanges code for token:
   POST https://blog.com/token
   {
     "grant_type": "authorization_code",
     "code": "xyz789",
     "client_id": "mobile-app",
     "client_secret": "secret123",
     "redirect_uri": "app://callback"
   }

7. Blog returns access token:
   {
     "access_token": "abc123",
     "token_type": "Bearer",
     "expires_in": 3600,
     "scope": "posts:read posts:write"
   }

8. Mobile App uses token to access API:
   GET https://blog.com/api/posts
   Authorization: Bearer abc123
```

### Implementation

```java
// 1. Client registration
public class OAuth2Client {
    private String clientId;
    private String clientSecret;
    private Set<String> allowedRedirectUris;
    private Set<String> allowedScopes;
}

// 2. Authorization endpoint
@GetMapping("/oauth/authorize")
public String authorize(
    @RequestParam String clientId,
    @RequestParam String redirectUri,
    @RequestParam String scope,
    @RequestParam String responseType,
    @RequestParam(required = false) String state,
    HttpSession session
) {
    // Check if user is logged in
    User user = SecurityContext.getCurrentUser();
    if (user == null) {
        // Redirect to login, then back here
        return "redirect:/login?returnTo=" + currentUrl;
    }

    // Validate client
    OAuth2Client client = clientRepository.findByClientId(clientId);
    if (client == null) {
        throw new InvalidClientException();
    }

    // Validate redirect URI
    if (!client.getAllowedRedirectUris().contains(redirectUri)) {
        throw new InvalidRedirectUriException();
    }

    // Show consent screen
    return "consent-page"; // User approves scopes
}

// 3. User approves (form submission)
@PostMapping("/oauth/authorize")
public String approveAuthorization(
    @RequestParam String clientId,
    @RequestParam String redirectUri,
    @RequestParam Set<String> scopes,
    @RequestParam(required = false) String state
) {
    User user = SecurityContext.getCurrentUser();

    // Generate authorization code
    String code = UUID.randomUUID().toString();

    AuthorizationCode authCode = new AuthorizationCode();
    authCode.setCode(code);
    authCode.setClientId(clientId);
    authCode.setUser(user);
    authCode.setRedirectUri(redirectUri);
    authCode.setScopes(scopes);
    authCode.setExpiresAt(Instant.now().plus(10, ChronoUnit.MINUTES));

    authCodeRepository.save(authCode);

    // Redirect back to client with code
    String redirectUrl = redirectUri + "?code=" + code;
    if (state != null) {
        redirectUrl += "&state=" + state;
    }

    return "redirect:" + redirectUrl;
}

// 4. Token endpoint
@PostMapping("/oauth/token")
public TokenResponse exchangeCodeForToken(
    @RequestParam String grantType,
    @RequestParam String code,
    @RequestParam String clientId,
    @RequestParam String clientSecret,
    @RequestParam String redirectUri
) {
    // Validate client credentials
    OAuth2Client client = clientRepository.findByClientId(clientId);
    if (client == null || !client.getClientSecret().equals(clientSecret)) {
        throw new InvalidClientException();
    }

    // Validate authorization code
    AuthorizationCode authCode = authCodeRepository.findByCode(code);

    if (authCode == null ||
        authCode.getExpiresAt().isBefore(Instant.now()) ||
        !authCode.getClientId().equals(clientId) ||
        !authCode.getRedirectUri().equals(redirectUri)) {
        throw new InvalidGrantException();
    }

    // Generate access token
    AccessToken accessToken = new AccessToken();
    accessToken.setToken(UUID.randomUUID().toString());
    accessToken.setUser(authCode.getUser());
    accessToken.setClientId(clientId);
    accessToken.setScopes(authCode.getScopes());
    accessToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

    tokenRepository.save(accessToken);

    // Delete authorization code (single use!)
    authCodeRepository.delete(authCode);

    return new TokenResponse(
        accessToken.getToken(),
        "Bearer",
        3600,
        authCode.getScopes()
    );
}
```

### 🎉 Why This Is Brilliant!

| Feature | Benefit |
|---------|---------|
| **No password sharing** | User authenticates on trusted site |
| **User consent** | User sees exactly what's requested |
| **Scoped access** | Limit what app can do |
| **Revocable** | Revoke token without password change |
| **Short-lived code** | Authorization code expires in minutes |
| **Client authentication** | Client secret validates app identity |
| **State parameter** | Prevents CSRF attacks |

---

## 🔑 Version 3: Refresh Tokens

### The Problem

Access tokens expire in 1 hour. User must re-authorize every hour? 😫

### The Solution

Issue two tokens:
1. **Access Token** - short-lived (1 hour), used for API calls
2. **Refresh Token** - long-lived (days/months), used to get new access tokens

```java
// 1. Issue both tokens
@PostMapping("/oauth/token")
public TokenResponse exchangeCodeForToken(...) {
    // ... validation ...

    // Generate access token (short-lived)
    AccessToken accessToken = createAccessToken(user, scopes, 3600);

    // Generate refresh token (long-lived)
    RefreshToken refreshToken = new RefreshToken();
    refreshToken.setToken(UUID.randomUUID().toString());
    refreshToken.setUser(user);
    refreshToken.setClientId(clientId);
    refreshToken.setScopes(scopes);
    refreshToken.setExpiresAt(Instant.now().plus(30, ChronoUnit.DAYS));

    refreshTokenRepository.save(refreshToken);

    return new TokenResponse(
        accessToken.getToken(),
        "Bearer",
        3600,
        scopes,
        refreshToken.getToken()  // Include refresh token
    );
}

// 2. Refresh token endpoint
@PostMapping("/oauth/token")
public TokenResponse refreshToken(
    @RequestParam String grantType,
    @RequestParam String refreshToken,
    @RequestParam String clientId,
    @RequestParam String clientSecret
) {
    if (!"refresh_token".equals(grantType)) {
        throw new InvalidGrantException();
    }

    // Validate client
    OAuth2Client client = authenticateClient(clientId, clientSecret);

    // Validate refresh token
    RefreshToken refresh = refreshTokenRepository.findByToken(refreshToken);

    if (refresh == null ||
        refresh.getExpiresAt().isBefore(Instant.now()) ||
        !refresh.getClientId().equals(clientId)) {
        throw new InvalidGrantException();
    }

    // Issue new access token
    AccessToken accessToken = createAccessToken(
        refresh.getUser(),
        refresh.getScopes(),
        3600
    );

    return new TokenResponse(
        accessToken.getToken(),
        "Bearer",
        3600,
        refresh.getScopes()
    );
}
```

### Client Usage

```java
public class BlogApiClient {
    private String accessToken;
    private String refreshToken;

    public List<Post> getPosts() {
        try {
            return apiCall("/posts", accessToken);
        } catch (UnauthorizedException e) {
            // Access token expired, refresh it
            refreshAccessToken();
            return apiCall("/posts", accessToken);
        }
    }

    private void refreshAccessToken() {
        TokenResponse response = http.post("/oauth/token")
            .param("grant_type", "refresh_token")
            .param("refresh_token", refreshToken)
            .param("client_id", clientId)
            .param("client_secret", clientSecret)
            .execute();

        this.accessToken = response.getAccessToken();
    }
}
```

### 🎉 Benefits

- ✅ Seamless user experience (no re-authorization)
- ✅ Security (access tokens short-lived)
- ✅ Control (can revoke refresh tokens)

---

## 🌐 Version 4: Different Grant Types

Not all clients are the same! OAuth2 defines different flows:

### Grant Type Comparison

| Grant Type | Use Case | Example |
|------------|----------|---------|
| **Authorization Code** | Web/Mobile apps with backend | Mobile app, SPA with backend |
| **Implicit** | ⚠️ Deprecated (insecure) | Old SPAs |
| **Client Credentials** | Machine-to-machine | Microservice, cron job |
| **Password** | ⚠️ Avoid (requires password) | Legacy migration |
| **Refresh Token** | Get new access token | All long-lived apps |

### Client Credentials Flow

For machine-to-machine authentication (no user involved):

```java
@PostMapping("/oauth/token")
public TokenResponse clientCredentials(
    @RequestParam String grantType,
    @RequestParam String clientId,
    @RequestParam String clientSecret,
    @RequestParam(required = false) String scope
) {
    if (!"client_credentials".equals(grantType)) {
        throw new InvalidGrantException();
    }

    // Validate client
    OAuth2Client client = clientRepository.findByClientId(clientId);
    if (client == null || !client.getClientSecret().equals(clientSecret)) {
        throw new InvalidClientException();
    }

    // Parse requested scopes
    Set<String> requestedScopes = parseScopes(scope);

    // Check if client is allowed these scopes
    if (!client.getAllowedScopes().containsAll(requestedScopes)) {
        throw new InvalidScopeException();
    }

    // Generate token (no user, only client)
    AccessToken accessToken = new AccessToken();
    accessToken.setToken(UUID.randomUUID().toString());
    accessToken.setClientId(clientId);
    accessToken.setUser(null); // No user!
    accessToken.setScopes(requestedScopes);
    accessToken.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));

    tokenRepository.save(accessToken);

    return new TokenResponse(
        accessToken.getToken(),
        "Bearer",
        3600,
        requestedScopes
    );
}
```

---

## 🎭 Version 5: OpenID Connect (OIDC)

### The Problem

OAuth2 is for **authorization** (delegating access).
But users want **authentication** (login with Google/Facebook).

### The Confusion

```
User clicks: "Login with Google"
Developer thinks: "OAuth2 gives me access token,
                   I'll call /userinfo to get identity"
```

But OAuth2 doesn't standardize:
- User info endpoint
- User info format
- How to request user info

### OpenID Connect Solution

OIDC = OAuth2 + standardized authentication

```java
// 1. Request includes 'openid' scope
@GetMapping("/oauth/authorize")
public String authorize(
    @RequestParam String scope,  // Contains "openid"
    // ... other params
) {
    Set<String> scopes = parseScopes(scope);

    // If 'openid' scope requested, this is OIDC
    boolean isOidc = scopes.contains("openid");

    // ... rest of flow
}

// 2. Token response includes ID Token
@PostMapping("/oauth/token")
public TokenResponse exchangeCodeForToken(...) {
    // ... validation ...

    AccessToken accessToken = createAccessToken(...);
    RefreshToken refreshToken = createRefreshToken(...);

    // If OIDC, create ID Token (JWT)
    String idToken = null;
    if (scopes.contains("openid")) {
        idToken = createIdToken(user, clientId, scopes);
    }

    return new TokenResponse(
        accessToken.getToken(),
        "Bearer",
        3600,
        scopes,
        refreshToken.getToken(),
        idToken  // ID Token
    );
}

// 3. ID Token is a JWT with user claims
private String createIdToken(User user, String clientId, Set<String> scopes) {
    Map<String, Object> claims = new HashMap<>();

    // Standard claims
    claims.put("iss", "https://blog.com");  // Issuer
    claims.put("sub", user.getId());         // Subject (user ID)
    claims.put("aud", clientId);             // Audience (client)
    claims.put("exp", Instant.now().plus(1, ChronoUnit.HOURS).getEpochSecond());
    claims.put("iat", Instant.now().getEpochSecond());

    // Optional claims based on scopes
    if (scopes.contains("profile")) {
        claims.put("name", user.getName());
        claims.put("picture", user.getAvatarUrl());
    }

    if (scopes.contains("email")) {
        claims.put("email", user.getEmail());
        claims.put("email_verified", user.isEmailVerified());
    }

    // Sign JWT
    return jwtService.createToken(claims);
}

// 4. Standardized UserInfo endpoint
@GetMapping("/oauth/userinfo")
public UserInfo getUserInfo(@RequestHeader("Authorization") String authorization) {
    String accessToken = extractToken(authorization);

    AccessToken token = tokenRepository.findByToken(accessToken);
    if (token == null || token.getExpiresAt().isBefore(Instant.now())) {
        throw new InvalidTokenException();
    }

    User user = token.getUser();
    Set<String> scopes = token.getScopes();

    UserInfo userInfo = new UserInfo();
    userInfo.setSub(user.getId());

    if (scopes.contains("profile")) {
        userInfo.setName(user.getName());
        userInfo.setPicture(user.getAvatarUrl());
    }

    if (scopes.contains("email")) {
        userInfo.setEmail(user.getEmail());
        userInfo.setEmailVerified(user.isEmailVerified());
    }

    return userInfo;
}
```

### OIDC Scopes

| Scope | Claims Included |
|-------|----------------|
| `openid` | Required, enables OIDC |
| `profile` | name, picture, birthdate, etc. |
| `email` | email, email_verified |
| `address` | formatted address |
| `phone` | phone_number, phone_number_verified |

### 🎉 Why OIDC Matters

- ✅ Standardized authentication
- ✅ ID Token contains identity (no extra API call)
- ✅ Standard UserInfo endpoint
- ✅ Works across all providers (Google, Microsoft, etc.)

---

# Part 6: Spring Security

Now that we understand WHY, let's see HOW Spring Security implements all this!

## 🏗️ Architecture Overview

Spring Security is essentially everything we just built, but:
- **Production-ready**
- **Highly configurable**
- **Supports many protocols**
- **Battle-tested**

### Core Components

```
Request
  ↓
SecurityFilterChain
  ├─ SecurityContextPersistenceFilter (loads authentication)
  ├─ UsernamePasswordAuthenticationFilter (login)
  ├─ OAuth2AuthorizationRequestRedirectFilter (OAuth2 start)
  ├─ OAuth2LoginAuthenticationFilter (OAuth2 callback)
  ├─ ExceptionTranslationFilter (handles auth errors)
  └─ AuthorizationFilter (checks permissions)
  ↓
Controller
```

### Key Abstractions

| Our Concept | Spring Security Equivalent |
|-------------|---------------------------|
| SecurityContext | SecurityContextHolder |
| User | UserDetails / Authentication |
| AuthenticationProvider | AuthenticationProvider |
| Filter Chain | SecurityFilterChain |
| @RequireRole | @Secured / @PreAuthorize |
| OAuth2Client | ClientRegistration |
| AccessToken | OAuth2AccessToken |

---

## 🔧 Spring Security Configuration

### Basic Setup

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Configure URL authorization
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // Configure login
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
            )
            // Configure logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
            );

        return http.build();
    }
}
```

### What's Happening Behind the Scenes?

```java
// This configuration:
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/admin/**").hasRole("ADMIN")
)

// Creates this filter:
public class AuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain
    ) throws ServletException, IOException {

        // Get current authentication
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // Check if request matches pattern
        if (pathMatcher.match("/admin/**", request.getRequestURI())) {
            // Check if user has ADMIN role
            boolean hasRole = auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));

            if (!hasRole) {
                throw new AccessDeniedException("Access denied");
            }
        }

        chain.doFilter(request, response);
    }
}
```

---

## 👤 UserDetailsService

Remember our User class? Spring Security uses `UserDetails`:

```java
// 1. UserDetails interface
public interface UserDetails {
    String getUsername();
    String getPassword();
    Collection<? extends GrantedAuthority> getAuthorities();
    boolean isAccountNonExpired();
    boolean isAccountNonLocked();
    boolean isCredentialsNonExpired();
    boolean isEnabled();
}

// 2. Your User entity
@Entity
public class User {
    @Id
    private Long id;
    private String username;
    private String password;
    private Set<Role> roles;

    // Convert to UserDetails
    public UserDetails toUserDetails() {
        return org.springframework.security.core.userdetails.User.builder()
            .username(username)
            .password(password)
            .authorities(roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toSet()))
            .build();
    }
}

// 3. UserDetailsService implementation
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(username));

        return user.toUserDetails();
    }
}

// 4. Configuration
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

### How Login Works

```java
// 1. User submits login form
POST /login
username=john&password=secret

// 2. UsernamePasswordAuthenticationFilter intercepts
public class UsernamePasswordAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    @Override
    public Authentication attemptAuthentication(
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        // Create authentication token
        UsernamePasswordAuthenticationToken token =
            new UsernamePasswordAuthenticationToken(username, password);

        // Delegate to AuthenticationManager
        return this.getAuthenticationManager().authenticate(token);
    }
}

// 3. AuthenticationManager delegates to providers
public class ProviderManager implements AuthenticationManager {

    @Override
    public Authentication authenticate(Authentication auth) {
        for (AuthenticationProvider provider : providers) {
            if (provider.supports(auth.getClass())) {
                return provider.authenticate(auth);
            }
        }
        throw new ProviderNotFoundException();
    }
}

// 4. DaoAuthenticationProvider checks credentials
public class DaoAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    @Override
    protected void additionalAuthenticationChecks(
        UserDetails user,
        UsernamePasswordAuthenticationToken token
    ) {
        String presentedPassword = token.getCredentials().toString();

        if (!passwordEncoder.matches(presentedPassword, user.getPassword())) {
            throw new BadCredentialsException("Bad credentials");
        }
    }

    @Override
    protected UserDetails retrieveUser(
        String username,
        UsernamePasswordAuthenticationToken token
    ) {
        return userDetailsService.loadUserByUsername(username);
    }
}

// 5. On success, authentication stored in SecurityContext
SecurityContext context = SecurityContextHolder.getContext();
context.setAuthentication(authentication);
```

---

## 🔐 Method Security

Remember `@PreAuthorize`? Here's how it works:

```java
// 1. Enable method security
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
    // That's it! Annotation processing is automatic
}

// 2. Use annotations
@Service
public class PostService {

    @PreAuthorize("hasRole('ADMIN')")
    public void deleteAllPosts() {
        postRepository.deleteAll();
    }

    @PreAuthorize("hasRole('USER') and #post.author.username == authentication.name")
    public Post updatePost(Post post) {
        return postRepository.save(post);
    }

    @PostAuthorize("returnObject.author.username == authentication.name or hasRole('ADMIN')")
    public Post getPost(Long id) {
        return postRepository.findById(id).orElseThrow();
    }
}

// 3. Behind the scenes: AOP proxy
@Component
public class MethodSecurityInterceptor {

    public Object invoke(MethodInvocation invocation) throws Throwable {
        Method method = invocation.getMethod();

        // Check @PreAuthorize
        PreAuthorize preAuth = method.getAnnotation(PreAuthorize.class);
        if (preAuth != null) {
            boolean authorized = expressionEvaluator.evaluate(
                preAuth.value(),
                SecurityContextHolder.getContext()
            );

            if (!authorized) {
                throw new AccessDeniedException("Access denied");
            }
        }

        // Execute method
        Object result = invocation.proceed();

        // Check @PostAuthorize
        PostAuthorize postAuth = method.getAnnotation(PostAuthorize.class);
        if (postAuth != null) {
            boolean authorized = expressionEvaluator.evaluate(
                postAuth.value(),
                SecurityContextHolder.getContext(),
                result  // returnObject
            );

            if (!authorized) {
                throw new AccessDeniedException("Access denied");
            }
        }

        return result;
    }
}
```

### Common Expressions

| Expression | Meaning |
|------------|---------|
| `hasRole('ADMIN')` | User has ADMIN role |
| `hasAnyRole('ADMIN', 'MODERATOR')` | User has any of the roles |
| `hasAuthority('posts:write')` | User has specific authority |
| `isAuthenticated()` | User is logged in |
| `isAnonymous()` | User is not logged in |
| `#param == authentication.name` | Method parameter equals current username |
| `returnObject.owner == authentication.name` | Return value owner matches current user |

---

## 🔗 OAuth2 Client Configuration

Remember the OAuth2 flow we built? Here's the Spring Security version:

```java
@Configuration
public class OAuth2ClientConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
            );

        return http.build();
    }
}
```

### Configuration Properties

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope:
              - openid
              - profile
              - email

          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope:
              - user:email
              - read:user

        provider:
          google:
            authorization-uri: https://accounts.google.com/o/oauth2/v2/auth
            token-uri: https://oauth2.googleapis.com/token
            user-info-uri: https://www.googleapis.com/oauth2/v3/userinfo
            user-name-attribute: sub
```

### What This Does

```java
// 1. User clicks "Login with Google"
GET /oauth2/authorization/google

// 2. OAuth2AuthorizationRequestRedirectFilter builds URL
public class OAuth2AuthorizationRequestRedirectFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(...) {
        ClientRegistration client = clientRegistrationRepository.findByRegistrationId("google");

        String authorizationUrl = client.getProviderDetails().getAuthorizationUri()
            + "?client_id=" + client.getClientId()
            + "&redirect_uri=" + baseUrl + "/login/oauth2/code/google"
            + "&response_type=code"
            + "&scope=" + String.join(" ", client.getScopes())
            + "&state=" + generateState();

        response.sendRedirect(authorizationUrl);
    }
}

// 3. User authorizes on Google, redirected back
GET /login/oauth2/code/google?code=xyz789&state=abc123

// 4. OAuth2LoginAuthenticationFilter handles callback
public class OAuth2LoginAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    @Override
    public Authentication attemptAuthentication(...) {
        String code = request.getParameter("code");
        String state = request.getParameter("state");

        // Validate state (CSRF protection)
        validateState(state);

        // Exchange code for token
        OAuth2AccessToken accessToken = exchangeCodeForToken(code);

        // Get user info
        OAuth2User user = getUserInfo(accessToken);

        // Create authentication
        return new OAuth2AuthenticationToken(user, authorities, "google");
    }
}
```

### Accessing OAuth2 User

```java
@RestController
public class UserController {

    @GetMapping("/user")
    public Map<String, Object> getUser(@AuthenticationPrincipal OAuth2User user) {
        // Access user attributes
        return Map.of(
            "name", user.getAttribute("name"),
            "email", user.getAttribute("email"),
            "picture", user.getAttribute("picture")
        );
    }

    // Alternative: Use Authentication
    @GetMapping("/user2")
    public Map<String, Object> getUser2(Authentication authentication) {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User user = token.getPrincipal();

        return user.getAttributes();
    }
}
```

---

## 🛡️ OAuth2 Resource Server

Now let's be the API that validates tokens!

### Configuration

```java
@Configuration
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );

        return http.build();
    }
}
```

### Properties

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://auth.example.com
          # OR
          jwk-set-uri: https://auth.example.com/.well-known/jwks.json
```

### How Token Validation Works

```java
// 1. Client sends request with token
GET /api/posts
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

// 2. BearerTokenAuthenticationFilter extracts token
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(...) {
        String token = extractToken(request);

        if (token != null) {
            // Create authentication token
            BearerTokenAuthenticationToken authToken =
                new BearerTokenAuthenticationToken(token);

            // Delegate to AuthenticationManager
            Authentication auth = authenticationManager.authenticate(authToken);

            // Store in SecurityContext
            SecurityContextHolder.getContext().setAuthentication(auth);
        }

        chain.doFilter(request, response);
    }
}

// 3. JwtAuthenticationProvider validates JWT
public class JwtAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication auth) {
        BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) auth;

        // Decode and validate JWT
        Jwt jwt = jwtDecoder.decode(token.getToken());

        // JWT validation includes:
        // - Signature verification (using public key from jwk-set-uri)
        // - Expiration check
        // - Issuer check
        // - Audience check (if configured)

        // Extract authorities from JWT claims
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);

        // Create authenticated token
        return new JwtAuthenticationToken(jwt, authorities);
    }

    private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        // Extract from 'scope' claim (OAuth2 standard)
        String scopes = jwt.getClaimAsString("scope");
        if (scopes != null) {
            return Arrays.stream(scopes.split(" "))
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toList());
        }

        // Or extract from 'authorities' claim (custom)
        List<String> authorities = jwt.getClaimAsStringList("authorities");
        if (authorities != null) {
            return authorities.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        }

        return Collections.emptyList();
    }
}
```

### Using JWT Claims

```java
@RestController
public class PostController {

    @GetMapping("/posts")
    @PreAuthorize("hasAuthority('SCOPE_posts:read')")
    public List<Post> getPosts(@AuthenticationPrincipal Jwt jwt) {
        // Access JWT claims
        String userId = jwt.getSubject();
        String scope = jwt.getClaimAsString("scope");

        return postRepository.findAll();
    }
}
```

---

## 🔑 OAuth2 Authorization Server

Finally, let's BE the authorization server!

### Setup (Spring Authorization Server)

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
</dependency>
```

### Configuration

```java
@Configuration
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        http
            .getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());  // Enable OpenID Connect

        http
            .exceptionHandling(exceptions -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(Customizer.withDefaults())
            );

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
            .authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // Register OAuth2 clients
        RegisteredClient mobileApp = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("mobile-app")
            .clientSecret("{noop}secret")  // Use BCrypt in production!
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .redirectUri("app://callback")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope("posts:read")
            .scope("posts:write")
            .clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(true)  // Show consent screen
                .build())
            .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofHours(1))
                .refreshTokenTimeToLive(Duration.ofDays(30))
                .reuseRefreshTokens(false)
                .build())
            .build();

        return new InMemoryRegisteredClientRepository(mobileApp);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Generate RSA key pair for signing JWTs
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
            .issuer("https://auth.example.com")
            .build();
    }
}
```

### What Endpoints Are Created?

| Endpoint | Purpose |
|----------|---------|
| `/oauth2/authorize` | Start authorization (get code) |
| `/oauth2/token` | Exchange code for token |
| `/oauth2/introspect` | Validate token |
| `/oauth2/revoke` | Revoke token |
| `/oauth2/jwks` | Public keys for JWT verification |
| `/.well-known/oauth-authorization-server` | Server metadata |
| `/.well-known/openid-configuration` | OIDC configuration |
| `/userinfo` | Get user info (OIDC) |

### Customizing JWT Claims

```java
@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
    return context -> {
        // Add custom claims to JWT
        if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
            Authentication auth = context.getPrincipal();
            UserDetails user = (UserDetails) auth.getPrincipal();

            context.getClaims()
                .claim("user_id", getUserId(user))
                .claim("email", getEmail(user))
                .claim("roles", user.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList()));
        }
    };
}
```

---

# Part 7: Practical Implementation Guide

## 🚀 Complete Working Example

Let's build a complete blog application with Spring Security and OAuth2!

### Project Structure

```
blog-app/
├── src/main/java/
│   └── com/example/blog/
│       ├── config/
│       │   ├── SecurityConfig.java
│       │   └── OAuth2ClientConfig.java
│       ├── controller/
│       │   ├── AuthController.java
│       │   ├── PostController.java
│       │   └── ApiController.java
│       ├── model/
│       │   ├── User.java
│       │   ├── Post.java
│       │   └── Role.java
│       ├── repository/
│       │   ├── UserRepository.java
│       │   └── PostRepository.java
│       ├── service/
│       │   ├── UserService.java
│       │   └── PostService.java
│       └── security/
│           └── CustomUserDetailsService.java
└── src/main/resources/
    ├── application.yml
    └── templates/
        ├── login.html
        └── posts.html
```

---

### Step 1: Dependencies

```xml
<dependencies>
    <!-- Spring Boot Starter -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>

    <!-- Spring Security -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>

    <!-- OAuth2 Client -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-client</artifactId>
    </dependency>

    <!-- OAuth2 Resource Server -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-oauth2-resource-server</artifactId>
    </dependency>

    <!-- Database -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>com.h2database</groupId>
        <artifactId>h2</artifactId>
        <scope>runtime</scope>
    </dependency>

    <!-- Thymeleaf (for templates) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
</dependencies>
```

---

### Step 2: Domain Models

```java
// User.java
@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    @ElementCollection(fetch = FetchType.EAGER)
    @Enumerated(EnumType.STRING)
    private Set<Role> roles = new HashSet<>();

    @OneToMany(mappedBy = "author", cascade = CascadeType.ALL)
    private List<Post> posts = new ArrayList<>();

    // Getters and setters
}

// Role.java
public enum Role {
    USER,
    MODERATOR,
    ADMIN
}

// Post.java
@Entity
@Table(name = "posts")
public class Post {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String content;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "author_id", nullable = false)
    private User author;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    private Instant updatedAt;

    @Column(nullable = false)
    private boolean published = false;

    // Getters and setters
}
```

---

### Step 3: Repositories

```java
// UserRepository.java
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
}

// PostRepository.java
@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    List<Post> findByAuthor(User author);
    List<Post> findByPublishedTrue();
}
```

---

### Step 4: UserDetailsService

```java
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException {

        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(
                "User not found: " + username
            ));

        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .collect(Collectors.toSet()))
            .build();
    }
}
```

---

### Step 5: Security Configuration

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/public/**", "/auth/register").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/**").authenticated()
                .anyRequest().authenticated()
            )

            // Form login
            .formLogin(form -> form
                .loginPage("/login")
                .defaultSuccessUrl("/posts")
                .permitAll()
            )

            // OAuth2 login
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/posts")
                .userInfoEndpoint(userInfo -> userInfo
                    .userService(oAuth2UserService())
                )
            )

            // Logout
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .permitAll()
            )

            // CSRF (keep enabled for web forms)
            .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/**")  // Disable for API
            )

            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false)
            );

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService() {
        DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();

        return request -> {
            OAuth2User oauth2User = delegate.loadUser(request);

            // Get user details from OAuth2 provider
            String email = oauth2User.getAttribute("email");
            String name = oauth2User.getAttribute("name");

            // Find or create user in our database
            User user = userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setEmail(email);
                    newUser.setUsername(email);
                    newUser.setPassword("");  // No password for OAuth2 users
                    newUser.setRoles(Set.of(Role.USER));
                    return userRepository.save(newUser);
                });

            // Return OAuth2User with our authorities
            return new DefaultOAuth2User(
                user.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                    .collect(Collectors.toSet()),
                oauth2User.getAttributes(),
                "email"
            );
        };
    }
}
```

---

### Step 6: Application Properties

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:blogdb
    driver-class-name: org.h2.Driver
    username: sa
    password:

  jpa:
    hibernate:
      ddl-auto: create-drop
    show-sql: true

  security:
    oauth2:
      client:
        registration:
          google:
            client-id: ${GOOGLE_CLIENT_ID}
            client-secret: ${GOOGLE_CLIENT_SECRET}
            scope:
              - openid
              - profile
              - email

          github:
            client-id: ${GITHUB_CLIENT_ID}
            client-secret: ${GITHUB_CLIENT_SECRET}
            scope:
              - user:email
              - read:user

logging:
  level:
    org.springframework.security: DEBUG
```

---

### Step 7: Controllers

```java
// AuthController.java
@Controller
public class AuthController {

    @Autowired
    private UserService userService;

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/auth/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/auth/register")
    public String register(
        @RequestParam String username,
        @RequestParam String email,
        @RequestParam String password
    ) {
        userService.register(username, email, password);
        return "redirect:/login?registered";
    }
}

// PostController.java
@Controller
public class PostController {

    @Autowired
    private PostService postService;

    @GetMapping("/posts")
    public String listPosts(Model model, Authentication authentication) {
        List<Post> posts = postService.getPublishedPosts();
        model.addAttribute("posts", posts);
        model.addAttribute("currentUser", authentication.getName());
        return "posts";
    }

    @GetMapping("/posts/my")
    public String myPosts(Model model, Authentication authentication) {
        List<Post> posts = postService.getUserPosts(authentication.getName());
        model.addAttribute("posts", posts);
        return "my-posts";
    }

    @PreAuthorize("hasRole('USER')")
    @PostMapping("/posts")
    public String createPost(
        @RequestParam String title,
        @RequestParam String content,
        Authentication authentication
    ) {
        postService.createPost(title, content, authentication.getName());
        return "redirect:/posts/my";
    }

    @PreAuthorize("@postSecurity.isOwner(#id) or hasRole('ADMIN')")
    @PostMapping("/posts/{id}/delete")
    public String deletePost(@PathVariable Long id) {
        postService.deletePost(id);
        return "redirect:/posts/my";
    }
}

// ApiController.java (REST API with JWT)
@RestController
@RequestMapping("/api")
public class ApiController {

    @Autowired
    private PostService postService;

    @GetMapping("/posts")
    public List<Post> getPosts() {
        return postService.getPublishedPosts();
    }

    @PostMapping("/posts")
    @PreAuthorize("hasAuthority('SCOPE_posts:write')")
    public Post createPost(@RequestBody Post post, @AuthenticationPrincipal Jwt jwt) {
        String username = jwt.getClaimAsString("username");
        return postService.createPost(post.getTitle(), post.getContent(), username);
    }

    @DeleteMapping("/posts/{id}")
    @PreAuthorize("hasAuthority('SCOPE_posts:delete') and @postSecurity.isOwner(#id)")
    public void deletePost(@PathVariable Long id) {
        postService.deletePost(id);
    }
}
```

---

### Step 8: Services

```java
// UserService.java
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User register(String username, String email, String password) {
        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setRoles(Set.of(Role.USER));

        return userRepository.save(user);
    }

    public User findByUsername(String username) {
        return userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(username));
    }
}

// PostService.java
@Service
public class PostService {

    @Autowired
    private PostRepository postRepository;

    @Autowired
    private UserRepository userRepository;

    public List<Post> getPublishedPosts() {
        return postRepository.findByPublishedTrue();
    }

    public List<Post> getUserPosts(String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(username));
        return postRepository.findByAuthor(user);
    }

    public Post createPost(String title, String content, String username) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException(username));

        Post post = new Post();
        post.setTitle(title);
        post.setContent(content);
        post.setAuthor(user);
        post.setPublished(true);
        post.setCreatedAt(Instant.now());

        return postRepository.save(post);
    }

    public void deletePost(Long id) {
        postRepository.deleteById(id);
    }
}

// PostSecurity.java (for SpEL expressions)
@Component("postSecurity")
public class PostSecurity {

    @Autowired
    private PostRepository postRepository;

    public boolean isOwner(Long postId) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) return false;

        String username = auth.getName();

        Post post = postRepository.findById(postId).orElse(null);
        if (post == null) return false;

        return post.getAuthor().getUsername().equals(username);
    }
}
```

---

## 🎯 Testing the Application

### Test 1: Form Login

```bash
# 1. Start application
mvn spring-boot:run

# 2. Register a user
curl -X POST http://localhost:8080/auth/register \
  -d "username=john" \
  -d "email=john@example.com" \
  -d "password=secret123"

# 3. Login (browser or curl)
curl -X POST http://localhost:8080/login \
  -d "username=john" \
  -d "password=secret123" \
  -c cookies.txt

# 4. Create a post
curl -X POST http://localhost:8080/posts \
  -b cookies.txt \
  -d "title=My First Post" \
  -d "content=Hello World"
```

### Test 2: OAuth2 Login

1. Set environment variables:
```bash
export GOOGLE_CLIENT_ID=your-client-id
export GOOGLE_CLIENT_SECRET=your-client-secret
```

2. Visit `http://localhost:8080/login`
3. Click "Login with Google"
4. Authorize the application
5. You're logged in!

### Test 3: JWT API

```bash
# 1. Get JWT token (from your auth server)
TOKEN=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...

# 2. Call API with token
curl -X GET http://localhost:8080/api/posts \
  -H "Authorization: Bearer $TOKEN"

# 3. Create post via API
curl -X POST http://localhost:8080/api/posts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "API Post",
    "content": "Created via API"
  }'
```

---

## 🔍 Debugging Tips

### Enable Security Debug Logging

```yaml
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.security.oauth2: TRACE
```

### Common Issues and Solutions

| Issue | Cause | Solution |
|-------|-------|----------|
| 403 Forbidden after login | CSRF token missing | Add CSRF token to forms or disable for API |
| Redirect loop | Login page requires authentication | Add `.permitAll()` to login page matcher |
| OAuth2 error | Wrong redirect URI | Match redirect URI in provider configuration |
| Token not validated | Wrong issuer | Check `issuer-uri` matches token issuer |
| Method security not working | @EnableMethodSecurity missing | Add annotation to config class |

### Inspect Security Context

```java
@GetMapping("/debug")
public String debug() {
    Authentication auth = SecurityContextHolder.getContext().getAuthentication();

    return "User: " + auth.getName() + "\n" +
           "Authorities: " + auth.getAuthorities() + "\n" +
           "Authenticated: " + auth.isAuthenticated();
}
```

---

## 📚 Key Takeaways

### The "Why" Behind Everything

1. **Filter Chain**
   - **Why**: Separate security concerns from business logic
   - **How**: Process requests before they reach controllers

2. **Authentication Providers**
   - **Why**: Support multiple authentication methods
   - **How**: Strategy pattern with pluggable providers

3. **SecurityContext**
   - **Why**: Make user info available everywhere
   - **How**: Thread-local storage

4. **Roles & Authorities**
   - **Why**: Control what users can do
   - **How**: Grant authorities, check in filters/annotations

5. **OAuth2 Authorization Code Flow**
   - **Why**: Delegate access without sharing passwords
   - **How**: Three-party flow: user, client, auth server

6. **Access & Refresh Tokens**
   - **Why**: Balance security and usability
   - **How**: Short-lived access token, long-lived refresh token

7. **JWT**
   - **Why**: Stateless, verifiable tokens
   - **How**: Signed JSON with claims

8. **OIDC**
   - **Why**: Standardized authentication on top of OAuth2
   - **How**: Add 'openid' scope, ID token with user claims

---

## 🎓 What You've Learned

You now understand:

✅ **Why** we need security (not just how)
✅ **How** authentication evolved (passwords → sessions → tokens)
✅ **Why** OAuth2 exists (delegation without password sharing)
✅ **How** OAuth2 works (authorization code flow step-by-step)
✅ **What** Spring Security provides (production-ready implementation)
✅ **How** to implement it in your projects

### Next Steps

1. **Practice**: Build the example application
2. **Experiment**: Try different grant types
3. **Read**: Spring Security documentation (you'll understand it now!)
4. **Implement**: Add security to your existing projects

---

## 📖 Further Reading

### Official Documentation
- [Spring Security Reference](https://docs.spring.io/spring-security/reference/)
- [OAuth 2.0 RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

### Key Concepts to Explore
- **PKCE (Proof Key for Code Exchange)**: Enhanced security for public clients
- **Token Introspection**: Validate opaque tokens
- **Token Revocation**: Invalidate tokens before expiration
- **Client Registration**: Dynamic client registration
- **Device Flow**: OAuth2 for devices without browsers

---

## 🎉 Congratulations!

You've gone from "zero" to understanding Spring Security and OAuth2 from first principles!

**Remember**: Every complex framework is just a solution to a series of problems. By understanding the problems first, you understand the framework naturally.

Now go build something secure! 🔒

---

*This guide was created with love for developers who want to truly understand, not just copy-paste.*

*Questions? Feedback? The best way to solidify your understanding is to teach others or build something!*
