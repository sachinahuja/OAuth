package moofwd.auth;

import static moofwd.auth.OutputUtils.say;
import static moofwd.auth.OutputUtils.shout;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import moofwd.auth.Service.Response;

import org.apache.commons.codec.binary.Base64;

public class Utils {

	public static final String O_HEADER			= "Authorization";
	
	//OAuth 1.0 Signature params
	public static final String HMAC_SHA1		= "HMAC-SHA1";
	public static final String EMPTY_STRING 	= "";
	public static final String CARRIAGE_RETURN 	= "\r\n";
	public static final String UTF8 			= "UTF-8";
	
	//OAuth 1.0 Default METHOD
	public static final String METHOD				= "POST";
	public static final String CONTENT_TYPE 		= "Content-Type";
	public static final String DEFAULT_CONTENT_TYPE = "application/x-www-form-urlencoded";
		
		
	public static  String getBaseString(Map<String, String> authParams, String url)throws UnsupportedEncodingException{
		return getBaseString(authParams, url, "POST");
	}
	
	public static String getBaseString(Map<String, String> authParams, String url, String method)throws UnsupportedEncodingException{
		say("V1: getBaseString");
		StringBuffer params = new StringBuffer();
		List<String> paramKeys = new ArrayList<String>(authParams.keySet());
		Collections.sort(paramKeys);
		for (String key : paramKeys) {
			if (params.length()>0)
				params.append("&");
			params.append(PercentEncoder.encode(key)).append("=").append(PercentEncoder.encode(authParams.get(key)));
		}
		
		String baseString = method
							+ "&"
							+ PercentEncoder.encode(url)
							+ "&"
							+ PercentEncoder.encode(params.toString());
		
		System.out.println("BAse String: "+baseString);
		return baseString;
	}
	
	public static  String getHeaderString(Map<String, String> authParams)throws UnsupportedEncodingException{
		StringBuffer sbf = null; 
		Set<Entry<String, String>> entries = authParams.entrySet();
		for (Entry<String, String> entry : entries) {
			if (sbf==null)
				sbf = new StringBuffer("OAuth ");
			else
				sbf.append(", ");
			sbf.append(entry.getKey()).append("=").append("\"").append(PercentEncoder.encode(entry.getValue())).append("\"");
		}
		System.out.println("Header String ::: "+sbf.toString());
		return sbf.toString();
	}
	
	//Step 3 ----- Get request token from the provider
	public static  String sign(String toSign, String secretKey)throws Exception{
		SecretKeySpec key = new SecretKeySpec(secretKey.getBytes(UTF8), HMAC_SHA1);
	    Mac mac = Mac.getInstance("HmacSHA1");
	    mac.init(key);
	    byte[] bytes = mac.doFinal(toSign.getBytes(UTF8));
	    String y = new String(Base64.encodeBase64(bytes)).replace(CARRIAGE_RETURN, EMPTY_STRING);
		System.out.println("BASE 64 String :::: "+y);
		return y;
	}	
	
	public static String getSecretKey(String token1, String token2)throws UnsupportedEncodingException{
		if (token2==null)
			return token1+"&";
//		String t1 = URLEncoder.encode(token1, "UTF-8");
//		String t2 = URLEncoder.encode(token2, "UTF-8");
		shout("token #1:: "+token1+" & token #2: "+token2);
		return PercentEncoder.encode(token1) + "&" + PercentEncoder.encode(token2);
	}
	
	public static Response doMethod(String method, String url, Map<String, String> headers, Map<String, String> params){
		Response resp = null;
		method = method.toUpperCase();
		if ("POST".equals(method))
			resp = post(url,headers,params);
		else
			resp = get(url, headers, params);
		
		return resp;
	}
	
	public static Response get(String url, Map<String, String> headers, Map<String,String> params){
		try{
		//Lets set params
		StringBuffer qStr = new StringBuffer("?");
		Set<String> keys = params.keySet();
		for (String key : keys) {
			qStr.append(PercentEncoder.encode(key)).append("=").append(PercentEncoder.encode(params.get(key))).append("&");
		}
		url = url + qStr.substring(0,qStr.length()-1);
		Response resp = connect("GET", url,params,headers);
		return resp;
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	public static Response post(String url, Map<String, String> headers, Map<String,String> params){
		try{
		Response resp = connect("POST", url, params, headers);
		return resp;
		}catch(Exception e){
			e.printStackTrace();
			return null;
		}
	}
	
	private static Response connect(String method, String url, Map<String,String> params, Map<String,String> headers)throws ProtocolException, MalformedURLException, IOException, UnsupportedEncodingException{
		HttpURLConnection connection = (HttpURLConnection)new URL(url).openConnection();
		connection.setRequestMethod(method);
		if (headers!=null)
			connection.setRequestProperty(O_HEADER, getHeaderString(headers));
		connection.setRequestProperty(CONTENT_TYPE, DEFAULT_CONTENT_TYPE);
		connection.setDoOutput(true);
		if (params!=null && ("POST".equals(method) || "PUT".equals(method))){
			addPostBody(connection, params);
		}
		
		
		connection.connect();
		int code = connection.getResponseCode();
		Response resp = new Response(code);
		shout("Response from Provider: "+resp.responseCode+" ... "+resp.isError);
		InputStream is = null;
		if (resp.isError){
			shout("Error!!");
			is = connection.getErrorStream();
		} else {
			shout("Done!!");
			is = connection.getInputStream();
		}
		//InputStream is = (resp.isError)?connection.getErrorStream():connection.getInputStream();
		String response = readStream(is);
		resp.response = response;
		
		connection.disconnect();
		return resp;
		
	}
	
	private static void addPostBody(HttpURLConnection connection, Map<String, String> params)throws IOException, UnsupportedEncodingException{
		Set<String> keys = params.keySet();
		StringBuffer bodyParams = new StringBuffer();
		for (String key : keys) {
				bodyParams.append(PercentEncoder.encode(key)).append("=").append(PercentEncoder.encode(params.get(key))).append("&");
		}
		String encodedParams = bodyParams.toString().substring(0, bodyParams.length()-1);
		shout("Encoded PARAMS: "+encodedParams);
		connection.getOutputStream().write(encodedParams.getBytes());
	}
	
	//Reading technique copied from http://stackoverflow.com/questions/309424/in-java-how-do-a-read-convert-an-inputstream-in-to-a-string
	private static String readStream(InputStream is)throws IOException{
		final char[] buffer = new char[0x10000];
		StringBuilder out = new StringBuilder();
		Reader in = new InputStreamReader(is, UTF8);
		int read;
		do {
		  read = in.read(buffer, 0, buffer.length);
		  if (read>0) {
		    out.append(buffer, 0, read);
		  }
		} while (read>=0);
		String responseBody = out.toString();
		shout("Response BODY:" +responseBody);
		in.close();
		is.close();
		return responseBody;
	}
	
	
	// This class is copied almost wholly from scribe-java
	// Hoping that his percent encoding implementation is based on real and exhaustive experience
	public static class PercentEncoder{
		
		
	private static final Set<EncodingRule> ENCODING_RULES;

	  static
	  {
	    Set<EncodingRule> rules = new HashSet<EncodingRule>();
	    rules.add(new EncodingRule("*","%2A"));
	    rules.add(new EncodingRule("+","%20"));
	    rules.add(new EncodingRule("%7E", "~"));
	    ENCODING_RULES = Collections.unmodifiableSet(rules);
	  }
	  
	  public static String encode(String str)throws UnsupportedEncodingException{
		  String encoded = URLEncoder.encode(str, UTF8);
		    for (EncodingRule rule : ENCODING_RULES)
		    {
		      encoded = rule.apply(encoded);
		    }
		    return encoded;
	  }
	
	private static final class EncodingRule
	  {
	    private final String ch;
	    private final String toCh;

	    EncodingRule(String ch, String toCh)
	    {
	      this.ch = ch;
	      this.toCh = toCh;
	    }

	    String apply(String string) {
	      return string.replace(ch, toCh);
	    }
	  }
	}
}

