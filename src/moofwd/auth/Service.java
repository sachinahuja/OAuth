package moofwd.auth;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.json.JSONException;
import org.json.JSONObject;

import moofwd.auth.OAuth.Owner;
import moofwd.auth.OAuth.Provider;


import static moofwd.auth.OutputUtils.*;
public abstract class Service{

	
	Provider provider;
	Consumer consumer;
	Owner owner;
	JSONObject accessToken;
	
	protected Service(Provider provider, Consumer consumer){
		this.provider = provider;
		this.consumer = consumer;
	}
	
	
	
	public abstract String authorize();
	protected abstract void processToken(String url);
	public abstract void execute(String resourceId, JSONObject data);
	
	
	
	public static Service service(Provider provider, Consumer consumer){
		if (provider.version==1)
			return new V1(provider, consumer);
		else
			return new V2(provider, consumer);
	}
	
	protected void extract(String response, Map<String, String> holder){
		say("SVC: extract data from response");
		String[] params = response.split("&");
		for (String param : params) {
			String[] keyVal = param.split("=");
			holder.put(keyVal[0], keyVal[1]);
		}
	}
	
	
	
	protected Map<String,String> extractQueryParams(String url){
		URI uri = URI.create(url);
		List<NameValuePair> nvp = URLEncodedUtils.parse(uri, "UTF-8");
		Map<String, String> map = new HashMap<String, String>();
		for (NameValuePair nameValuePair : nvp) {
			map.put(nameValuePair.getName(), nameValuePair.getValue());
		}
		return map;
	}	
	
	protected JSONObject extractAccessToken(String response) throws JSONException{
		
		JSONObject respJson = null;
		if (response.startsWith("{")){
			//this is json response
			respJson = new JSONObject(response);
		} else {
			//this is a query string response
			Hashtable<String, String> accessTokenData = new Hashtable<String, String>();
			extract(response, accessTokenData);
			respJson = new JSONObject(accessTokenData);
		}
		
		
		String at = respJson.getString(provider.accessTokenKey);
		String ats = respJson.optString(provider.accessTokenSecretKey);
		respJson.remove(provider.accessTokenKey);
		respJson.remove(provider.accessTokenSecretKey);
		owner = new Owner().token(at).secret(ats).data(respJson);
		return respJson;
		
	}
	
	public static class Response{
		String response;
		public boolean isError;
		int responseCode;
		public Response(int responseCode){
			this.responseCode = responseCode;
			isError = responseCode<200 || responseCode>=400;
		}
	}
}
