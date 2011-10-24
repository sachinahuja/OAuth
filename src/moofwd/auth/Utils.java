package moofwd.auth;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.http.client.HttpClient;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.util.EncodingUtils;
import org.yaml.snakeyaml.util.UriEncoder;

public class Utils {

	
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

