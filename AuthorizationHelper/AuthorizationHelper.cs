using Microsoft.AspNetCore.Http;

namespace AuthorizationHelper;

public class AuthorizationHelper {
	public static (string username, string password) GetBasicCredentials(HttpRequest request) {
		throw new NotImplementedException();
	}
}