using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Http;
using NUnit.Framework.Internal;

namespace AuthorizationHelper;

public class AuthorizationHelper {
	public static (string username, string password) GetBasicCredentials(HttpRequest request, ILogger logger = null) {
		if (!request.Headers.ContainsKey("Authorization")) {
			logger.Error("Basic auth header missing");
			return (null, null);
		}

		var authHeader = request.Headers["Authorization"].ToString();

		if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) {
			logger.Error("Invalid basic auth header");
			return (null, null);
		}

		var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Substring(6).Trim())).Split(':', 2);

		if (credentials.Length != 2) {
			logger.Error("Invalid basic auth header");
			return (null, null);
		}

		logger.Info("Basic credentials were extracted");
		return (credentials[0], credentials[1]);
	}

	public static string GetBearerToken(HttpRequest request, ILogger logger = null) {
		if (!request.Headers.ContainsKey("Authorization")) {
			logger.Error("Bearer auth header missing");
			return null;
		}

		var authHeader = request.Headers["Authorization"].ToString();

		if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
			logger.Error("Invalid bearer auth header");
			return null;
		}

		logger.Info("Bearer token was extracted");
		return authHeader.Substring(7).Trim();
	}

	public static bool IsTokenExpired(string token) {
		var jwtToken = new JwtSecurityTokenHandler().ReadToken(token) as JwtSecurityToken;

		if (jwtToken == null) return true;

		return jwtToken.ValidTo < DateTime.UtcNow;
	}

	public static (string username, string realm, string nonce, string uri, string response, string opaque) GetDigestCredentials
		(HttpRequest request, ILogger logger = null) {
		if (!request.Headers.ContainsKey("Authorization")) {
			logger.Error("Digest auth header missing");
			return (null, null, null, null, null, null);
		}

		var authHeader = request.Headers["Authorization"].ToString();

		if (!authHeader.StartsWith("Digest ", StringComparison.OrdinalIgnoreCase)) {
			logger.Error("Invalid digest auth header");
			return (null, null, null, null, null, null);
		}

		var digestValues = authHeader.Substring(7).Trim().Split(',');

		var digestDict = digestValues.Select(value => value.Split('=')).ToDictionary(pair => pair[0].Trim(), pair => pair[1].Trim(' ', '"'));

		digestDict.TryGetValue("username", out var username);
		digestDict.TryGetValue("realm", out var realm);
		digestDict.TryGetValue("nonce", out var nonce);
		digestDict.TryGetValue("uri", out var uri);
		digestDict.TryGetValue("response", out var response);
		digestDict.TryGetValue("opaque", out var opaque);

		logger.Info("Digest auth was extracted");
		return (username, realm, nonce, uri, response, opaque);
	}
}