package moofwd.auth;

import java.io.Serializable;

import org.json.JSONObject;



public class Consumer implements Serializable {

	long serialVersionUID=111110000;
	//static consumer info
	public String providerName;
	public String apiKey;
	public String apiSecret;
	public String callback;
	
	//generated consumer info
	public transient JSONObject accessToken;
	public String atStr;
	
	
	public Consumer(String providerName, String apiKey, String apiSecret, String callback){
		this.apiKey = apiKey;
		this.apiSecret = apiSecret;
		this.callback = callback;
		this.providerName = providerName;
	}
	
	public void setAccessToken(JSONObject accessToken){
		this.accessToken = accessToken;
		this.atStr = accessToken.toString();
	}
	
	
	
	
	
}
