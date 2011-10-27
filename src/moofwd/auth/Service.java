package moofwd.auth;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import org.json.JSONException;
import org.json.JSONObject;

import moofwd.auth.OAuth.Owner;
import moofwd.auth.OAuth.Provider;


import static moofwd.auth.OutputUtils.*;
public abstract class Service{

	protected static final String QUERY_DELIM = "?";
	
	public Provider provider;
	public Consumer consumer;
	public Owner owner;
	JSONObject accessToken;
	
	protected Service(Provider provider, Consumer consumer){
		this.provider = provider;
		this.consumer = consumer;
	}
	
	
	
	public abstract String authorize();
	public abstract void processToken(String url);
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
		try{
			URL yourl = new URL(url);
			String queryString = yourl.getQuery();
			String[] pairs = queryString.split("&");
			Map<String, String> queryMap = new HashMap<String,String>();
			for (String pair : pairs) {
				String[] keyVal = pair.split("=");
				queryMap.put(keyVal[0], keyVal[1]);
			}
			shout("Query Map: "+queryMap);
			return queryMap;
		}catch(MalformedURLException e){
			e.printStackTrace();
			return null;
		}
		
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
		setOwner(respJson);
		
		return respJson;
		
		
	}
	
	protected abstract void setOwner(JSONObject respJson)throws JSONException;
		
	
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
