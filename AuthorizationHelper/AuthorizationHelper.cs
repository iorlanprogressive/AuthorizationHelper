using System.Text;
using Microsoft.AspNetCore.Http;

namespace AuthorizationHelper;

public class AuthorizationHelper {
	public static (string username, string password) GetBasicCredentials(HttpRequest request) {
		if (!request.Headers.ContainsKey("Authorization")) return (null, null);

		var authHeader = request.Headers["Authorization"].ToString();

		if (!authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return (null, null);

		var credentials = Encoding.UTF8.GetString(Convert.FromBase64String(authHeader.Substring(6).Trim())).Split(':', 2);

		if (credentials.Length != 2) return (null, null);

		return (credentials[0], credentials[1]);
	}

	public static string GetBearerToken(HttpRequest request) {
		if (!request.Headers.ContainsKey("Authorization")) return null;

		var authHeader = request.Headers["Authorization"].ToString();

		if (!authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;

		return authHeader.Substring(7).Trim();
	}
}