package moofwd.auth;

import static moofwd.auth.OutputUtils.say;
import static moofwd.auth.OutputUtils.shout;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.HttpClient;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.util.EncodingUtils;
import org.yaml.snakeyaml.util.UriEncoder;

public class Utils {

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
	
	public static  String getHeaderString(Map<String, String> authParams)throws UnsupportedEncodingException{
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
		return URLEncoder.encode(token1, UTF8) + "&" + URLEncoder.encode(token2, UTF8);
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
		  String encoded = URLEncoder.encode(str, "UTF-8");
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

