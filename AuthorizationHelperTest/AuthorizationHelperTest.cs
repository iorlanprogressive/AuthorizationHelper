using System.Text;
using Microsoft.AspNetCore.Http;
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
}