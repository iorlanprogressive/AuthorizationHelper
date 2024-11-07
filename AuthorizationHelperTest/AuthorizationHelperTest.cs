using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Moq;

namespace AuthorizationHelperTest;

[TestFixture]
public class AuthorizationHelperTests {
	private HttpRequest GetMockHttpRequest(HeaderDictionary headers) {
		var request = new Mock<HttpRequest>();
		request.Setup(r => r.Headers).Returns(headers);
		return request.Object;
	}

	[Test]
	public void GetBasicCredentials_WithValidBasicAuthHeader_ReturnsCredentials() {
		var result = AuthorizationHelper.AuthorizationHelper.GetBasicCredentials
			(GetMockHttpRequest(new HeaderDictionary { { "Authorization", "Basic " + Convert.ToBase64String("username:password"u8.ToArray()) } }));

		Assert.AreEqual("username", result.username);
		Assert.AreEqual("password", result.password);
	}

	[Test]
	public void GetBasicCredentials_WithInvalidBasicAuthHeader_ReturnsNull() {
		var result = AuthorizationHelper.AuthorizationHelper.GetBasicCredentials
			(
			 GetMockHttpRequest
				 (new HeaderDictionary { { "Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("invalid_credentials")) } })
			);

		Assert.IsNull(result.username);
		Assert.IsNull(result.password);
	}

	[Test]
	public void GetBasicCredentials_WithoutAuthHeader_ReturnsNull() {
		var result = AuthorizationHelper.AuthorizationHelper.GetBasicCredentials(GetMockHttpRequest(new HeaderDictionary()));

		Assert.IsNull(result.username);
		Assert.IsNull(result.password);
	}

	[Test]
	public void GetBearerToken_WithValidBearerAuthHeader_ReturnsToken() {
		Assert.That
			(
			 AuthorizationHelper.AuthorizationHelper.GetBearerToken
				 (GetMockHttpRequest(new HeaderDictionary { { "Authorization", "Bearer valid_token" } })),
			 Is.EqualTo("valid_token")
			);
	}

	[Test]
	public void GetBearerToken_WithInvalidBearerAuthHeader_ReturnsNull() {
		Assert.IsNull
			(
			 AuthorizationHelper.AuthorizationHelper.GetBearerToken
				 (GetMockHttpRequest(new HeaderDictionary { { "Authorization", "InvalidBearerToken" } }))
			);
	}

	[Test]
	public void GetBearerToken_WithoutBearerAuthHeader_ReturnsNull() {
		Assert.IsNull(AuthorizationHelper.AuthorizationHelper.GetBearerToken(GetMockHttpRequest(new HeaderDictionary())));
	}

	[Test]
	public void IsTokenExpired_ExpiredToken_ReturnsTrue() {
		Assert.IsTrue(AuthorizationHelper.AuthorizationHelper.IsTokenExpired(CreateJwtToken(DateTime.UtcNow.AddMinutes(-1))));
	}

	[Test]
	public void IsTokenExpired_ValidToken_ReturnsFalse() {
		Assert.IsFalse(AuthorizationHelper.AuthorizationHelper.IsTokenExpired(CreateJwtToken(DateTime.UtcNow.AddMinutes(1))));
	}

	[Test]
	public void GetDigestCredentials_WithValidDigestAuthHeader_ReturnsCredentials() {
		var result = AuthorizationHelper.AuthorizationHelper.GetDigestCredentials
			(
			 GetMockHttpRequest
				 (
				  new HeaderDictionary {
					  {
						  "Authorization",
						  "Digest username=\"user\", realm=\"realm\", nonce=\"nonce\", uri=\"/uri\", response=\"response\", opaque=\"opaque\""
					  }
				  }
				 )
			);
		Assert.AreEqual("user", result.username);
		Assert.AreEqual("realm", result.realm);
		Assert.AreEqual("nonce", result.nonce);
		Assert.AreEqual("/uri", result.uri);
		Assert.AreEqual("response", result.response);
		Assert.AreEqual("opaque", result.opaque);
	}

	[Test]
	public void GetDigestCredentials_WithInvalidDigestAuthHeader_ReturnsNull() {
		var result = AuthorizationHelper.AuthorizationHelper.GetDigestCredentials
			(GetMockHttpRequest(new HeaderDictionary { { "Authorization", "InvalidHeader" } }));
		Assert.IsNull(result.username);
		Assert.IsNull(result.realm);
		Assert.IsNull(result.nonce);
		Assert.IsNull(result.uri);
		Assert.IsNull(result.response);
		Assert.IsNull(result.opaque);
	}

	[Test]
	public void GetDigestCredentials_WithoutAuthHeader_ReturnsNull() {
		var result = AuthorizationHelper.AuthorizationHelper.GetDigestCredentials(GetMockHttpRequest(new HeaderDictionary()));
		Assert.IsNull(result.username);
		Assert.IsNull(result.realm);
		Assert.IsNull(result.nonce);
		Assert.IsNull(result.uri);
		Assert.IsNull(result.response);
		Assert.IsNull(result.opaque);
	}

	private string CreateJwtToken(DateTime expiration) {
		var tokenHandler = new JwtSecurityTokenHandler();
		var token = tokenHandler.CreateToken(new SecurityTokenDescriptor { NotBefore = DateTime.UtcNow.AddYears(-1), Expires = expiration });
		return tokenHandler.WriteToken(token);
	}
}