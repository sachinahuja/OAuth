package moofwd.auth;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import moofwd.auth.OAuth.Owner;
import moofwd.auth.OAuth.Provider;
import moofwd.auth.OAuth.Resource;

import org.json.JSONException;
import org.json.JSONObject;

import static moofwd.auth.OutputUtils.*;
import static moofwd.auth.Utils.*;

public class V2 extends Service {

	private static final String CODE 			= "code";
	private static final String CLIENT_ID 		= "client_id";
	private static final String CLIENT_SECRET	= "client_secret";
	private static final String REDIR_URL 		= "redirect_uri";

	protected V2(Provider provider, Consumer consumer){
		super(provider, consumer);
	}
	
	public void execute(String resourceId, JSONObject data){
		try{
			Resource resource = provider.getResource(resourceId);
			String resourceUrl = provider.getResourceAsUrl(resourceId, data);
			Map<String, String> queryParams = resource.getParams(data);
			queryParams.put("access_token", owner.accessToken);
			Response response = doMethod(resource.method, resourceUrl, null, queryParams);
			//Use the response!
		
		}catch(Exception e){
			e.printStackTrace();
		}
	}

	public String authorize() {
		try{
		String auth_url =  String.format(provider.authUrl, consumer.apiKey, URLEncoder.encode(consumer.callback, "UTF-8"));
		shout(provider.name+" auth url::: "+auth_url);
		return auth_url;
		}catch(UnsupportedEncodingException e){
			e.printStackTrace();
			return null;
		}
	}

	public void processToken(String url) {
		
		try{
		Map<String, String> queryParams = extractQueryParams(url);
		String code = queryParams.get(provider.codeKey);
		if (code==null){
			shout("No Code in response!: "+url);
		} else {
			//Lets get the "real" access token
			Map<String, String> params = new HashMap<String,String>();
			params.put(CODE,code);
			params.put(CLIENT_ID, consumer.apiKey);
			params.put(CLIENT_SECRET,consumer.apiSecret);
			params.put(REDIR_URL,consumer.callback);
			Response atResponse = get(provider.accessTokenUrl, null, params);
			String accessTokenResp = atResponse.response;//getAccessToken(code);
			say("Response from "+provider.name+" :: "+accessTokenResp);
			accessToken = extractAccessToken(accessTokenResp);
			say("Here's the accessToken :"+accessToken);
			 
			
		}
		} catch(Exception e){
			e.printStackTrace();
		}
			
	}
	
	
	protected void setOwner(JSONObject respJson)throws JSONException{
		String at = respJson.getString(provider.accessTokenKey);
		respJson.remove(provider.accessTokenKey);
		owner = new Owner().token(at).data(respJson);
	}
	

}
