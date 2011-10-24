package moofwd.auth;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Hashtable;
import java.util.Map;

import moofwd.auth.OAuth.Provider;

import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.json.JSONException;
import org.json.JSONObject;

import static moofwd.auth.OutputUtils.*;

public class V2 extends Service {

	protected V2(Provider provider, Consumer consumer){
		super(provider, consumer);
	}
	
	public void execute(String resourceId, JSONObject data){
	
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

	protected void processToken(String url) {
		
		try{
		Map<String, String> queryParams = extractQueryParams(url);
		String code = queryParams.get(provider.codeKey);
		if (code==null){
			shout("No Code in response!: "+url);
		} else {
			//Lets get the "real" access token
			String accessTokenResp = getAccessToken(code);
			accessToken = extractAccessToken(accessTokenResp);
			say("Here's the accessToken :"+accessToken);
			 
			
		}
		} catch(Exception e){
			//this.oauthCallback.setErrorMessage("Error extracting authorization code from "+provider.name+" response");
			
			e.printStackTrace();
		}
			
	}
	
	private String getAccessToken(String code) throws IOException{
		
		HttpClient client = new DefaultHttpClient();
		String url = String.format(provider.accessTokenUrl, consumer.apiKey, consumer.apiSecret, URLEncoder.encode(consumer.callback,"UTF-8"), code);
		HttpGet get = new HttpGet(url);
		HttpResponse response = client.execute(get);
		String respStr = EntityUtils.toString(response.getEntity());
		return respStr;
		
	}
	
	

}
