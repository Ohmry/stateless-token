# 개요
이 문서는 테스트 코드를 작성하기 위해 AI가 참고하는 문서입니다. 모든 테스트는 단위테스트로 실제 서버를 구동하지 않고, Mock 객체를 이용해서 테스트를 수행합니다. 하나의 파일에 여러 개의 클래스를 만들지 않으며, 각 테스트 대상별로 테스트 파일을 나누어 작성합니다.

# 공통 사항
- 모든 주석은 영어로 작성합니다.

# 테스트 대상
테스트의 대상은 `io.github.ohmry.stateless.token.domain`에 있는 모든 클래스와 `io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder`가 대상입니다.

# 테스트 내용
각 클래스별로 아래와 같은 테스트 케이스를 작성해야 합니다.

## StatelessTokenPolicyHolder

### 패키지
io.github.ohmry.stateless.token.configuration.StatelessTokenPolicyHolder

### 테스트 항목

  - `application.yml` 파일에 프로퍼티를 선언하고, `StatelessTokenPolicyHolder` 클래스에서 해당 값들을 정상적으로 불러올 수 있는지 테스트한다. 테스트가 필요한 프로퍼티는 아래와 같다.
    - stateless.token.secret
    - stateless.token.timeout
    - stateless.accessToken.secret
    - stateless.accessToken.timeout
    - stateless.refreshToken.secret
    - stateless.refreshToken.timeout

  - @Bean 어노테이션을 이용해서 `StatelessTokenPolicy` 객체를 직접 등록하고, `StatelessTokenPolicyHolder` 클래스에서 해당 값들을 정상적으로 불러올 수 있는지 테스트한다.

  - 모든 테스트에서 값의 확인은 `StatelessTokenPolicy`에 정의된 Getter 함수를 참고하여 모든 Getter에 대한 값 검증을 수행한다.

  - SecretKey를 생성할 때, 알고리즘은 byte의 길이에 따라 달라지므로 아래 코드를 참고해서 테스트 코드를 작성한다. secret 문자열을 byte[]로 변환하고, 길이에 8을 곱한다.
    ```java
    public static SecretKey hmacShaKeyFor(byte[] bytes) throws WeakKeyException {
        if (bytes == null) {
            throw new InvalidKeyException("SecretKey byte array cannot be null.");
        } else {
            int bitLength = bytes.length * 8;
            if (bitLength >= 512) {
                return new SecretKeySpec(bytes, "HmacSHA512");
            } else if (bitLength >= 384) {
                return new SecretKeySpec(bytes, "HmacSHA384");
            } else if (bitLength >= 256) {
                return new SecretKeySpec(bytes, "HmacSHA256");
            } else {
                String msg = "The specified key byte array is " + bitLength + " bits which " + "is not secure enough for any JWT HMAC-SHA algorithm.  The JWT " + "JWA Specification (RFC 7518, Section 3.2) states that keys used with HMAC-SHA algorithms MUST have a " + "size >= 256 bits (the key size must be greater than or equal to the hash " + "output size).  Consider using the Jwts.SIG.HS256.key() builder (or HS384.key() " + "or HS512.key()) to create a key guaranteed to be secure enough for your preferred HMAC-SHA " + "algorithm.  See https://tools.ietf.org/html/rfc7518#section-3.2 for more information.";
                throw new WeakKeyException(msg);
            }
        }
    }
    ```

## Token
### 패키지
io.github.ohmry.stateless.token.domain.Token

### 테스트 항목

- 기본 테스트인 생성, 파싱, 만료에 대한 테스트를 작성한다.
- 프로퍼티를 이용해서 SecretKey와 Timeout 값을 변경한 뒤 그 값에 맞게 객체가 생성되는지 테스트한다.
  - stateless.token.secret
  - stateless.token.timeout
- @Bean 등록을 이용해서 SecretKey와 Timeout 값을 변경한 뒤 그 값에 맞게 객체가 생성되는지 테스트한다.
- 토큰 문자열을 파싱하여 객체가 정상적으로 생성되는지 테스트한다.
- 만료된 토큰 문자열을 파싱하여 객체를 생성했을 때, 만료된 객체로 만들어지는지 테스트한다.
- Subject의 경우 간단한 User 클래스를 만들어서 테스트하고, Map 객체를 만들어서 각각 테스트 케이스를 작성한다.
- Map 객체로 테스트하는 경우 parse(String tokenValue, Type type) 함수를 이용해서 테스트한다.

## AccessToken
### 패키지
io.github.ohmry.stateless.token.domain.AccessToken

### 테스트 항목
- 기본 테스트인 생성, 파싱, 만료에 대한 테스트를 작성한다.
- 프로퍼티를 이용해서 SecretKey와 Timeout 값을 변경한 뒤 그 값에 맞게 객체가 생성되는지 테스트한다. `stateless.accessToken.secret`에 대한 값이 없을 경우 `stateless.token.secret`의 값을 사용하고, `stateless.accessToken.timeout`에 대한 값이 없을 경우 기본 타임아웃은 5분을 적용한다.
    - stateless.token.secret
    - stateless.accessToken.secret
    - stateless.accessToken.timeout
- @Bean 등록을 이용해서 SecretKey와 Timeout 값을 변경한 뒤 그 값에 맞게 객체가 생성되는지 테스트한다.
- 토큰 문자열을 파싱하여 객체가 정상적으로 생성되는지 테스트한다.
- 만료된 토큰 문자열을 파싱하여 객체를 생성했을 때, 만료된 객체로 만들어지는지 테스트한다.
- Subject의 경우 간단한 User 클래스를 만들어서 테스트하고, Map 객체를 만들어서 각각 테스트 케이스를 작성한다.
- Map 객체로 테스트하는 경우 parse(String tokenValue, Type type) 함수를 이용해서 테스트한다.

## RefreshToken
### 패키지
io.github.ohmry.stateless.token.domain.RefreshToken

### 테스트 항목
- 기본 테스트인 생성, 파싱, 만료에 대한 테스트를 작성한다.
- 프로퍼티를 이용해서 SecretKey와 Timeout 값을 변경한 뒤 그 값에 맞게 객체가 생성되는지 테스트한다. `stateless.refreshToken.secret`에 대한 값이 없을 경우 `stateless.token.secret`의 값을 사용하고, `stateless.refreshToken.timeout`에 대한 값이 없을 경우 기본 타임아웃은 5분을 적용한다.
    - stateless.token.secret
    - stateless.refreshToken.secret
    - stateless.refreshToken.timeout
- @Bean 등록을 이용해서 SecretKey와 Timeout 값을 변경한 뒤 그 값에 맞게 객체가 생성되는지 테스트한다.
- 토큰 문자열을 파싱하여 객체가 정상적으로 생성되는지 테스트한다.
- 만료된 토큰 문자열을 파싱하여 객체를 생성했을 때, 만료된 객체로 만들어지는지 테스트한다.
- Subject의 경우 간단한 User 클래스를 만들어서 테스트하고, Map 객체를 만들어서 각각 테스트 케이스를 작성한다.
- Map 객체로 테스트하는 경우 parse(String tokenValue, Type type) 함수를 이용해서 테스트한다.