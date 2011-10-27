package moofwd.auth;

import java.io.Serializable;
import java.io.UTFDataFormatException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;



import org.json.JSONException;
import org.json.JSONObject;


public class OAuth {

	public Providers<Provider> providers;
	
	public Provider getProvider(String name){
		return this.providers.get(name);
	}
	
	public static class Providers<T> extends ArrayList<Provider>{
		private Map<String, Provider> internal_providers = new HashMap<String, Provider>();
		
		
		
		@Override
		public Iterator<Provider> iterator() {
			return internal_providers.values().iterator();
		}
		public void put(Provider provider){
			this.internal_providers.put(provider.name, provider);
		}
		public Provider get(String providerName){
			return internal_providers.get(providerName);
		}
		public boolean add(Provider e) {
			put(e);
			return true;
		}
		
		
	}
	
	public static class Provider{
		public String name, baseApiUrl, authUrl, requestTokenUrl, accessTokenUrl, codeKey="code", tokenFormat="query";
		public String accessTokenKey="oauth_token", accessTokenSecretKey = "oauth_token_secret"; //this is based on twitter/oauth1.0a
		int version;
		public Resources<Resource> resources;
		public static Provider provider(String name){
			return new Provider().name(name);
		}
		
		public Provider name(String name){this.name=name;return this;}
		public Provider baseApiUrl(String baseApiUrl){this.baseApiUrl=baseApiUrl; return this;}
		public Provider version(int version){this.version=version;return this;}
		public Provider addResource(Resource resource){this.resources.put(resource); return this;}
		public Resource getResource(String resourceName){return this.resources.get(resourceName);}
		public String getResourceAsUrl(String resourceName, JSONObject input)throws Exception{
			Resource res = resources.get(resourceName);
			String resPath = res.getResourceAsUrl(input);
			String fullPath = baseApiUrl+resPath;
			return fullPath;
		}
	}
	
	
	public static class Resources<T> extends ArrayList<Resource>{
		private Map<String, Resource> internal_resources = new HashMap<String, Resource>();
		
		
		
		@Override
		public Iterator<Resource> iterator() {
			return internal_resources.values().iterator();
		}
		public void put(Resource resource){
			this.internal_resources.put(resource.id, resource);
		}
		public Resource get(String resourceId){
			return internal_resources.get(resourceId);
		}
		public boolean add(Resource e) {
			put(e);
			return true;
		}
		
		
	}
	
	public static class Resource{
		
		public String id, path, method, response, description;
		public String[] params;
		
		
		
		public static Resource resource(String id){
			return new Resource().id(id);
		}
		
		public Resource id(String id){this.id=id; return this;}
		public Resource path(String path){this.path=path;return this;}
		public Resource method(String method){this.method=method; return this;}
		public Resource responseType(String type){this.response=type;return this;}
		
		public String getResourceAsUrl(JSONObject input)throws Exception{
			Iterator<String> keys = input.keys();
			String localPath = path;
			while (keys.hasNext()) {
				String key = keys.next();
				if (localPath.contains(":"+key))
					localPath = localPath.replace(":"+key, URLEncoder.encode(input.getString(key), "UTF-8"));
			}
			
			System.out.println("Original Path: "+path);
			System.out.println("Configured Path: "+localPath);
			return localPath;
		}
		
		public Map<String, String> getParams(JSONObject data)throws JSONException{
			if (params==null) return new HashMap<String,String>();
			
			Map<String, String> paramsMap = new HashMap<String, String>();
			for (String param : params) {
				paramsMap.put(param, data.getString(param)); // we are treating every  param as 'required' ... will change that soon
			}
			return paramsMap;
		}
	}
	
	public static class Owner implements Serializable{
		/**
		 * 
		 */
		
		public String accessToken;
		public String accessTokenSecret;
		String accessTokenResponseInJSON;
		private transient JSONObject data;
		
		
		public Owner(String at, String ats, String atrij){
			this.accessToken = at;
			this.accessTokenSecret = ats;
			this.accessTokenResponseInJSON = atrij;
			
		}
		
		public Owner(){}
		
		public Owner owner(){return new Owner();}
		public Owner token(String token){this.accessToken = token;return this;}
		public Owner secret(String key){this.accessTokenSecret = key; return this;}
		public Owner data(JSONObject restOfTheData){
			this.data = restOfTheData;
			this.accessTokenResponseInJSON = data.toString();
			return this;
		}
		
		public JSONObject getData(){
			if (data!=null)
				return data;
			if (accessTokenResponseInJSON!=null){
				try{
					data = new JSONObject(accessTokenResponseInJSON);
				} catch (JSONException e){
					e.printStackTrace();
				}
			}
			
			return data;
				
		}
	}
			
	
}
	



