using System.Text;
using Microsoft.AspNetCore.Http;

namespace AuthorizationHelper;

public class AuthorizationHelper {
	public static (string username, string password) GetBasicCredentials(HttpRequest request) {
		if (request.Headers.ContainsKey("Authorization")) {
			var authHeader = request.Headers["Authorization"].ToString();
			if (authHeader.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) {
				var encodedCredentials = authHeader.Substring("Basic ".Length).Trim();
				var decodedCredentials = Encoding.UTF8.GetString(Convert.FromBase64String(encodedCredentials));
				var credentials = decodedCredentials.Split(':', 2);
				if (credentials.Length == 2) return (credentials[0], credentials[1]);
			}
		}

		return (null, null);
	}
}