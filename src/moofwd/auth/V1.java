package moofwd.auth;

import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import moofwd.auth.OAuth.Owner;
import moofwd.auth.OAuth.Resource;

import org.json.JSONException;
import org.json.JSONObject;

import static moofwd.auth.OutputUtils.*;
import static moofwd.auth.Utils.*;
public class V1 extends Service {

	//OAuth 1.0 Request Token Params
	public static final String O_CALLBACK 		= "oauth_callback";
	public static final String O_CONS_KEY 		= "oauth_consumer_key";
	public static final String O_NONCE 			= "oauth_nonce";
	public static final String O_SIGN_METHOD	= "oauth_signature_method";
	public static final String O_TIMESTAMP 		= "oauth_timestamp";
	public static final String O_VERSION		= "oauth_version";
	public static final String O_SIGNATURE		= "oauth_signature";
	public static final String O_HEADER			= "Authorization";
	
	//Access params
	public static final String O_VERIFIER 		= "oauth_verifier";
	public static final String O_TOKEN			= "oauth_token";
	public static final String O_TOKEN_SECRET	= "oauth_token_secret";
	//OAuth 1.0 Header params
	public static final String HDR_PREAMBLE		= "OAuth ";
	public static final String HDR_DELIM		= ", ";
	

	private Map<String, String> reqTokenParams;
	private Hashtable<String, String> accessTokenParams;
	
	
	//OAuth 1.0 --- Twitter config
//	static String req_url = "http://api.twitter.com/oauth/request_token";
//	static String api_key = "hWeQzINE6zicQDAtWXlHbQ";
//	static String api_secret = "TtAOatdyieThSn07bCivVdyiOdOX4cHDkLa4WOflRvk";
//	static String callback = "http://moofwd.com/oauth";
	
	
	
	
	protected V1(moofwd.auth.OAuth.Provider provider, Consumer consumer){
		super(provider, consumer);
		say("V1: created service");
	}
	
	public  String authorize() {
		try{
		say("V1: authorize!!");
		Map<String, String> authParams = getOAuthParams();
		String baseString = getBaseString(authParams, provider.requestTokenUrl);
		String signature = sign(baseString, getSecretKey(consumer.apiSecret, null));
		authParams.put(O_SIGNATURE, signature);
		
		//String header = getHeaderString(authParams);
		//Now, lets call the oauth provider
		Response resp =  post(provider.requestTokenUrl, authParams, null);// connectThruHttpClient(header, provider.requestTokenUrl);
		String response = resp.response;
		reqTokenParams = new HashMap<String, String>();
		extract(response, reqTokenParams);
		return String.format(provider.authUrl, reqTokenParams.get(O_TOKEN));
		
		} catch(Exception e){
			e.printStackTrace();
			return null;
		}
		
	}
	
	
	public void execute(String resourceId, JSONObject data){
		try{
			Resource resource = provider.getResource(resourceId);
			//boolean isPost = "post".equalsIgnoreCase(resource.method);
			String resourceUrl = provider.getResourceAsUrl(resourceId, data);
			Map<String, String> params = getAccessParams(null, owner.accessToken);
			String baseString = null;
			Map<String, String> postData = resource.getParams(data);
			Map<String, String> mergedMapForBaseString = new HashMap<String, String>();
			mergedMapForBaseString.putAll(params);
			mergedMapForBaseString.putAll(postData);
			baseString = getBaseString(mergedMapForBaseString, resourceUrl, resource.method.toUpperCase()); //a little confusion .. what to do with query params?
			
			 
			String secret = getSecretKey(consumer.apiSecret, owner.accessTokenSecret); //("MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA");//
			String signature = sign(baseString, secret);
			params.put(O_SIGNATURE, signature);
			Response resp = doMethod(resource.method, resourceUrl, params, postData);
			shout(resp.response);
			//String response = (isPost)?post(resourceUrl, params, postData):get(resourceUrl,params);
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	//Step 1 ---- Add OAuth Params to Map
	
	
	
	
	
	
	
	
	
	
	
	public void processToken(String url){
		say("V1: processing token from url: "+url);
		Map<String,String> params = extractQueryParams(url);
		String oauth_verifier = params.get(O_VERIFIER);
		Map<String, String> authParams = getAccessParams(oauth_verifier, reqTokenParams.get(O_TOKEN));
		try{
			String baseString = getBaseString(authParams, provider.accessTokenUrl);
			String secretKey = getSecretKey(consumer.apiSecret, reqTokenParams.get(O_TOKEN_SECRET));
			String signature = sign(baseString, secretKey);
			authParams.put(O_SIGNATURE, signature);
			//String header = getHeaderString(authParams);
			//Now, lets call the oauth provider
			Response resp = post(provider.accessTokenUrl, authParams, null);
			String response = resp.response;
					//connectThruHttpClient(header, provider.accessTokenUrl);
			System.out.println("Response:::: "+response);
			if (!response.contains(O_TOKEN)){
				
				shout("Error response from "+provider.name+" --->>> "+response);
				
			} else{
				accessToken = extractAccessToken(response);
				say("We got the access tokens!:: "+accessToken);
			}
			
			
		}catch(UnsupportedEncodingException e){
			e.printStackTrace();
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	private  Map<String, String> getOAuthParams(){
		Map<String, String> authParams = new HashMap<String, String>();
		authParams.put(O_CALLBACK, consumer.callback);
		authParams.put(O_CONS_KEY, consumer.apiKey);
		authParams.put(O_NONCE, nonce());
		authParams.put(O_SIGN_METHOD, HMAC_SHA1);
		authParams.put(O_TIMESTAMP, timeInSecs());
		authParams.put(O_VERSION, "1.0");
		return authParams;
	}
	
	private  Map<String, String> getAccessParams(String oauth_verifier, String token){
		Map<String, String> authParams = new HashMap<String, String>();
		authParams.put(O_CONS_KEY, consumer.apiKey);
		authParams.put(O_NONCE, nonce());
		authParams.put(O_SIGN_METHOD, HMAC_SHA1);
		authParams.put(O_TIMESTAMP, timeInSecs());
		authParams.put(O_VERSION, "1.0");
		authParams.put(O_TOKEN, token);
		if (oauth_verifier!=null)
			authParams.put(O_VERIFIER, oauth_verifier);
		return authParams;
	}
	
	protected void setOwner(JSONObject respJson)throws JSONException{
		String at = respJson.getString(provider.accessTokenKey);
		String ats = respJson.optString(provider.accessTokenSecretKey);
		respJson.remove(provider.accessTokenKey);
		respJson.remove(provider.accessTokenSecretKey);
		owner = new Owner().token(at).secret(ats).data(respJson);
		
	}
	
	//Util Methods
	private static String nonce(){
		long ts = ts();
		return String.valueOf(ts+randomInt());		
	}
	private static int randomInt(){
		return new Random().nextInt();
	}
	private static String timeInSecs(){
		return String.valueOf(ts());
	}
	
	private static long ts(){
		return System.currentTimeMillis()/1000;
	}
	
	
	
	/// List all algos --- test method to get the right string for hmac sha1. To be removed after cross OS testing
	public static void getCryptoImpls(String serviceType) {
	    	    
	    Provider[] providers = Security.getProviders();
	    for (Provider provider : providers) {
			Set keyset = provider.keySet();
			for (Object object : keyset) {
				String key = (String)object;
				System.out.println(key);
			}
		}
	    
	}
}
