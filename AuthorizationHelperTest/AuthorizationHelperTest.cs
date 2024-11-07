using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;
using Moq;
using NUnit.Framework.Internal;

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
		var loggerMock = new Mock<ILogger>();

		var result = AuthorizationHelper.AuthorizationHelper.GetBasicCredentials
			(
			 GetMockHttpRequest(new HeaderDictionary { { "Authorization", "Basic " + Convert.ToBase64String("username:password"u8.ToArray()) } }),
			 loggerMock.Object
			);

		Assert.AreEqual("username", result.username);
		Assert.AreEqual("password", result.password);
		loggerMock.Verify(l => l.Info("Basic credentials were extracted"), Times.Once);
	}

	[Test]
	public void GetBasicCredentials_WithInvalidBasicAuthHeader_ReturnsNull() {
		var loggerMock = new Mock<ILogger>();

		var result = AuthorizationHelper.AuthorizationHelper.GetBasicCredentials
			(
			 GetMockHttpRequest
				 (new HeaderDictionary { { "Authorization", "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes("invalid_credentials")) } }),
			 loggerMock.Object
			);

		Assert.IsNull(result.username);
		Assert.IsNull(result.password);

		loggerMock.Verify(l => l.Error("Invalid basic auth header"), Times.Once);
	}

	[Test]
	public void GetBasicCredentials_WithoutAuthHeader_ReturnsNull() {
		var loggerMock = new Mock<ILogger>();

		var result = AuthorizationHelper.AuthorizationHelper.GetBasicCredentials(GetMockHttpRequest(new HeaderDictionary()), loggerMock.Object);

		Assert.IsNull(result.username);
		Assert.IsNull(result.password);

		loggerMock.Verify(l => l.Error("Basic auth header missing"), Times.Once);
	}

	[Test]
	public void GetBearerToken_WithValidBearerAuthHeader_ReturnsToken() {
		var loggerMock = new Mock<ILogger>();

		Assert.That
			(
			 AuthorizationHelper.AuthorizationHelper.GetBearerToken
				 (GetMockHttpRequest(new HeaderDictionary { { "Authorization", "Bearer valid_token" } }), loggerMock.Object),
			 Is.EqualTo("valid_token")
			);

		loggerMock.Verify(l => l.Info("Bearer token was extracted"), Times.Once);
	}

	[Test]
	public void GetBearerToken_WithInvalidBearerAuthHeader_ReturnsNull() {
		var loggerMock = new Mock<ILogger>();

		Assert.IsNull
			(
			 AuthorizationHelper.AuthorizationHelper.GetBearerToken
				 (GetMockHttpRequest(new HeaderDictionary { { "Authorization", "InvalidBearerToken" } }), loggerMock.Object)
			);

		loggerMock.Verify(l => l.Error("Invalid bearer auth header"), Times.Once);
	}

	[Test]
	public void GetBearerToken_WithoutBearerAuthHeader_ReturnsNull() {
		var loggerMock = new Mock<ILogger>();

		Assert.IsNull(AuthorizationHelper.AuthorizationHelper.GetBearerToken(GetMockHttpRequest(new HeaderDictionary()), loggerMock.Object));

		loggerMock.Verify(l => l.Error("Bearer auth header missing"), Times.Once);
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
		var loggerMock = new Mock<ILogger>();

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
				 ),
			 loggerMock.Object
			);

		Assert.AreEqual("user", result.username);
		Assert.AreEqual("realm", result.realm);
		Assert.AreEqual("nonce", result.nonce);
		Assert.AreEqual("/uri", result.uri);
		Assert.AreEqual("response", result.response);
		Assert.AreEqual("opaque", result.opaque);

		loggerMock.Verify(l => l.Info("Digest auth was extracted"), Times.Once);
	}

	[Test]
	public void GetDigestCredentials_WithInvalidDigestAuthHeader_ReturnsNull() {
		var loggerMock = new Mock<ILogger>();

		var result = AuthorizationHelper.AuthorizationHelper.GetDigestCredentials
			(GetMockHttpRequest(new HeaderDictionary { { "Authorization", "InvalidHeader" } }), loggerMock.Object);

		Assert.IsNull(result.username);
		Assert.IsNull(result.realm);
		Assert.IsNull(result.nonce);
		Assert.IsNull(result.uri);
		Assert.IsNull(result.response);
		Assert.IsNull(result.opaque);

		loggerMock.Verify(l => l.Error("Invalid digest auth header"), Times.Once);
	}

	[Test]
	public void GetDigestCredentials_WithoutAuthHeader_ReturnsNull() {
		var loggerMock = new Mock<ILogger>();

		var result = AuthorizationHelper.AuthorizationHelper.GetDigestCredentials(GetMockHttpRequest(new HeaderDictionary()), loggerMock.Object);

		Assert.IsNull(result.username);
		Assert.IsNull(result.realm);
		Assert.IsNull(result.nonce);
		Assert.IsNull(result.uri);
		Assert.IsNull(result.response);
		Assert.IsNull(result.opaque);

		loggerMock.Verify(l => l.Error("Digest auth header missing"), Times.Once);
	}

	private string CreateJwtToken(DateTime expiration) {
		var loggerMock = new Mock<ILogger>();
		var tokenHandler = new JwtSecurityTokenHandler();
		var token = tokenHandler.CreateToken(new SecurityTokenDescriptor { NotBefore = DateTime.UtcNow.AddYears(-1), Expires = expiration });
		return tokenHandler.WriteToken(token);
	}
}