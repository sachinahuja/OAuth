package moofwd.auth;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Random;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import moofwd.auth.OAuth.Providers;
import moofwd.auth.OAuth.Resource;
import moofwd.auth.Utils.PercentEncoder;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;
import org.json.JSONObject;
import org.yaml.snakeyaml.util.UriEncoder;

import static moofwd.auth.OutputUtils.*;
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
	
	//OAuth 1.0 Signature params
	public static final String HMAC_SHA1		= "HMAC-SHA1";
	private static final String EMPTY_STRING = "";
	private static final String CARRIAGE_RETURN = "\r\n";
	private static final String UTF8 = "UTF-8";
	
	//OAuth 1.0 Default METHOD
	public static final String METHOD			= "POST";
	private static final String CONTENT_TYPE = "Content-Type";
	public static final String DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded";

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
		
		String header = getHeaderString(authParams);
		//Now, lets call the oauth provider
		String response = connectThruHttpClient(header, provider.requestTokenUrl);
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
			boolean isPost = "post".equalsIgnoreCase(resource.method);
			String resourceUrl = provider.getResourceAsUrl(resourceId, data);
			Map<String, String> params = getAccessParams(null, owner.accessToken);
			String baseString = null;
			Map<String, String> postData = new HashMap<String, String>();
			if (isPost){
				
				for (String param : resource.postParams) {
					postData.put(param, data.getString(param)); // we are treating every post param as 'required' ... will change that soon
				}
				
				Map<String, String> mergedMapForBaseString = new HashMap<String, String>();
				mergedMapForBaseString.putAll(params);
				mergedMapForBaseString.putAll(postData);
				baseString = getBaseString(mergedMapForBaseString, resourceUrl, "POST"); //a little confusion .. what to do with query params?
			} else {
				baseString = getBaseString(params, resourceUrl, "GET"); //a little confusion .. what to do with query params?
			}
			 
			String secret = getSecretKey(consumer.apiSecret, owner.accessTokenSecret); //("MCD8BKwGdgPHvAuvgvz4EQpqDAtx89grbuNMRd7Eh98", "J6zix3FfA9LofH0awS24M3HcBYXO5nI1iYe8EfBA");//
			String signature = sign(baseString, secret);
			params.put(O_SIGNATURE, signature);
			String response = (isPost)?post(resourceUrl, params, postData):get(resourceUrl,params);
			
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	private String get(String url, Map<String,String> header)throws UnsupportedEncodingException, ClientProtocolException, IOException{
		HttpClient client = new DefaultHttpClient();
		HttpGet get = new HttpGet(url);
		get.addHeader(O_HEADER, getHeaderString(header));
		get.addHeader(CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
		HttpResponse response = client.execute(get);
		String responseBody = EntityUtils.toString(response.getEntity());
		shout("Here's the RESPONSE from "+provider.name+" ===========>>>>>>>>>>");
		shout(responseBody);
		return responseBody;
	}
	private String post(String url, Map<String,String> header, Map<String,String> params)throws UnsupportedEncodingException, ClientProtocolException, IOException{
		//Lets try with Java.net
//		HttpURLConnection connection = (HttpURLConnection)new URL(url).openConnection();
//		connection.setRequestMethod("POST");
//		connection.setRequestProperty(O_HEADER, getHeaderString(header));
//		connection.setRequestProperty(CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
//		connection.setDoOutput(true);
//		String responseBody = null;
//		
//		Set<String> keys = params.keySet();
//		StringBuffer bodyParams = new StringBuffer();
//		for (String key : keys) {
//				bodyParams.append(URLEncoder.encode(key, UTF8)).append("=").append(URLEncoder.encode(params.get(key), UTF8)).append("&");
//		}
//		String encodedParams = bodyParams.toString().substring(0, bodyParams.length()-1);
//		shout("Encoded PARAMS: "+encodedParams);
//		connection.getOutputStream().write(encodedParams.getBytes());
//		connection.connect();
//		int responseCode = connection.getResponseCode();
//		boolean success = responseCode >= 200 && responseCode < 400; 
//		InputStream is = success?connection.getInputStream():connection.getErrorStream();
//		
//			//Success!!
//			
//			//Reading technique copied from http://stackoverflow.com/questions/309424/in-java-how-do-a-read-convert-an-inputstream-in-to-a-string
//			final char[] buffer = new char[0x10000];
//			StringBuilder out = new StringBuilder();
//			Reader in = new InputStreamReader(is, UTF8);
//			int read;
//			do {
//			  read = in.read(buffer, 0, buffer.length);
//			  if (read>0) {
//			    out.append(buffer, 0, read);
//			  }
//			} while (read>=0);
//			responseBody = out.toString();
//			shout("Response BODY:" +responseBody);
			
		
		
		
		
		
		
		
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(url);
		post.addHeader(O_HEADER, getHeaderString(header));
		post.addHeader(CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
		List<NameValuePair> postParams = new ArrayList<NameValuePair>();
		Set<String> keys = params.keySet();
		HttpParams httpParams = new BasicHttpParams();
		for (String key : keys) {
			
			httpParams.setParameter(key, URLEncoder.encode(params.get(key), UTF8));
			//String param = PercentEncoder.encode(params.get(key));
			//postParams.add(new BasicNameValuePair(key, param));
		}
		post.setParams(httpParams);
		
		//post.setEntity(new UrlEncodedFormEntity(postParams,HTTP.UTF_8));
		
		HttpResponse response = client.execute(post);
		String responseBody = EntityUtils.toString(response.getEntity());
		shout("Here's the RESPONSE from "+provider.name+" ===========>>>>>>>>>>");
		shout(responseBody);
		return responseBody;
	}
	
	private  String connectThruHttpClient(String header, String url)throws Exception{
		say("V1: connect");
		HttpClient client = new DefaultHttpClient();
		HttpPost post = new HttpPost(url);
		post.addHeader(O_HEADER, header);
		post.addHeader(CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
		HttpResponse response = client.execute(post);
		String responseBody = EntityUtils.toString(response.getEntity());
		System.out.println("REsponse::: "+responseBody);
		return responseBody;
		
	}
	
	
	
	
	
	//Step 1 ---- Add OAuth Params to Map
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
	
	
	private  String getBaseString(Map<String, String> authParams, String url)throws UnsupportedEncodingException{
		
		return getBaseString(authParams, url, "POST");
	
	}
	
	//Step 2 ---- Generate Base String from params
	private  String getBaseString(Map<String, String> authParams, String url, String method)throws UnsupportedEncodingException{
		say("V1: getBaseString");
		StringBuffer params = new StringBuffer();
		List<String> paramKeys = new ArrayList<String>(authParams.keySet());
		Collections.sort(paramKeys);
		for (String key : paramKeys) {
			if (params.length()>0)
				params.append("&");
			params.append(URLEncoder.encode(key, UTF8)).append("=").append(PercentEncoder.encode(authParams.get(key)));
		}
		
		String baseString = method
							+ "&"
							+ URLEncoder.encode(url, "UTF-8")
							+ "&"
							+ URLEncoder.encode(params.toString(), UTF8);
		
		System.out.println("BAse String: "+baseString);
		return baseString;
	}
	
	private  String getHeaderString(Map<String, String> authParams)throws UnsupportedEncodingException{
		StringBuffer sbf = null; 
		Set<Entry<String, String>> entries = authParams.entrySet();
		for (Entry<String, String> entry : entries) {
			if (sbf==null)
				sbf = new StringBuffer("OAuth ");
			else
				sbf.append(", ");
			sbf.append(entry.getKey()).append("=").append("\"").append(URLEncoder.encode(entry.getValue(), UTF8)).append("\"");
		}
		System.out.println("Header String ::: "+sbf.toString());
		return sbf.toString();
	}
	
	//Step 3 ----- Get request token from the provider
	private  String sign(String toSign, String secretKey)throws Exception{
		SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(UTF8), HMAC_SHA1);
	    Mac mac = Mac.getInstance("HmacSHA1");
	    mac.init(key);
	    byte[] bytes = mac.doFinal(toSign.getBytes(UTF8));
	    String y = new String(Base64.encodeBase64(bytes)).replace(CARRIAGE_RETURN, EMPTY_STRING);
		System.out.println("BASE 64 String :::: "+y);
		return y;
	}	
	
	private String getSecretKey(String token1, String token2)throws UnsupportedEncodingException{
		if (token2==null)
			return token1+"&";
//		String t1 = URLEncoder.encode(token1, "UTF-8");
//		String t2 = URLEncoder.encode(token2, "UTF-8");
		shout("token #1:: "+token1+" & token #2: "+token2);
		return URLEncoder.encode(token1, UTF8) + "&" + URLEncoder.encode(token2, UTF8);
	}
	
	
	
	
	
	protected void processToken(String url){
		say("V1: processing token from url: "+url);
		Map<String,String> params = extractQueryParams(url);
		String oauth_verifier = params.get(O_VERIFIER);
		Map<String, String> authParams = getAccessParams(oauth_verifier, reqTokenParams.get(O_TOKEN));
		try{
			String baseString = getBaseString(authParams, provider.accessTokenUrl);
			String secretKey = getSecretKey(consumer.apiSecret, reqTokenParams.get(O_TOKEN_SECRET));
			String signature = sign(baseString, secretKey);
			authParams.put(O_SIGNATURE, signature);
			String header = getHeaderString(authParams);
			//Now, lets call the oauth provider
			String response = connectThruHttpClient(header, provider.accessTokenUrl);
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
	
	
	
	/// List all algos
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
