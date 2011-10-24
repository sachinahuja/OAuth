package moofwd.auth;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import moofwd.auth.OAuth.Owner;
import moofwd.auth.OAuth.Provider;
import moofwd.auth.OAuth.Resource;
import moofwd.auth.OAuth.Resources;

import org.json.JSONObject;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

import static moofwd.auth.OutputUtils.*;

public class Test {

	
	public static void main(String[] args) throws Exception{
		say("Loading providers .... ");
		InputStream is = new FileInputStream("/Users/sachinahuja/moofwd_workspace/Moofwd-Auth/providers.yaml");
		Yaml yaml = new Yaml(new Constructor(OAuth.class));
		Object d = yaml.load(is);
		OAuth oauth = (OAuth)d;
		
		//Print Test
		for (Provider provider: oauth.providers){
			shout(provider.name+" / " + provider.authUrl);
			for (Resource resource : provider.resources) {
				shout("\t"+resource.id);
				if (resource.postParams!=null){
					for (String param : resource.postParams) {
						shout("\t\tParam: "+param);
					}
				}
					
			}
		}
		//Print Test Ends

		boolean skipConfig = false;
		Consumer consumer = null;
		Provider provider = null;
		Service service = null;
		Owner owner = null;
		Scanner in = new Scanner(System.in);
		
		say("==== Which provider would you like to load?");
		shout(">> ");
		String providerName = in.nextLine();
		String consumerDataFile = providerName+"_consumer.data";
		String ownerDataFile = providerName+"_owner.data";
		File cFile = new File(consumerDataFile);
		File oFile = new File(ownerDataFile);
		boolean loadConsumerFromFile=false , loadOwnerFromFile=false;
		
		provider = oauth.getProvider(providerName);
		say("Activated Provider \""+provider.name+"\"");
		if (cFile.exists()){
			say("You have already provided consumer info for "+providerName+", do you want to continue to use that (y/n)?");
			say(">> ");
			String cAnswer = in.nextLine();
			loadConsumerFromFile = "y".equalsIgnoreCase(cAnswer);
			
		}
		
		if (oFile.exists()){
			say("You have already authenticated with "+providerName+", do you want to continue to use that info (y/n)?");
			say(">> ");
			String oAnswer = in.nextLine();
			loadOwnerFromFile = "y".equalsIgnoreCase(oAnswer);
		}
		
		if (loadConsumerFromFile){
			ObjectInputStream oin = new ObjectInputStream(new FileInputStream(cFile));
			consumer = (Consumer)oin.readObject();
			oin.close();
			say("Loaded your info with apiKey: "+consumer.apiKey);
		} else {
			say("Lets get some data about your app!");
			say("Please provide your api key:");
			say(">>");
			String apiKey = in.nextLine();
			say("Please provide your api secret (don't worry i won't share it!):");
			say(">>");
			String apiSecret = in.nextLine();
			say("Please provide your callback url:");
			say(">>");
			String callback = in.nextLine();
			
			say("Thanks! Creating your consumer");
			consumer = new Consumer(providerName, apiKey, apiSecret, callback);
			
			ObjectOutput out = new ObjectOutputStream(new FileOutputStream(consumerDataFile));
			out.writeObject(consumer);
			out.close();
		}
		
		service = Service.service(provider, consumer);
		
		if (loadOwnerFromFile){
			ObjectInputStream oin = new ObjectInputStream(new FileInputStream(oFile));
			owner = (Owner)oin.readObject();
			oin.close();
			service.owner = owner;
			say("loaded owner with access token: "+owner.accessToken);
		} else {
			String authUrl = service.authorize();
			shout("I'll give you your auth url in a second ... first read this");
			shout("\t take the auth url and paste it in a browser .. follow the oauth dance and approve your app");
			shout("\t ONCE that's done, copy the redirect url that you see in you browser's address bar");
			shout("\t COME BACK here QUICKLY and paste it on the prompt");
			shout("Now, here's that auth url ....");
			say(authUrl+"\n");
			say(">> ");
			String url = in.nextLine();
			service.processToken(url);
			owner = service.owner;
			ObjectOutput out = new ObjectOutputStream(new FileOutputStream(ownerDataFile));
			out.writeObject(owner);
			out.close();
		}
		
		
		
		
		
			
			
			
		 
		say("OK, now we have everything to ping these providers... lets get on with it");
		say("Here's a list of Resources that you can request from "+provider.name);
		shout("================================");
		for (Resource res : provider.resources) {
			shout("\t"+res.id);
		}
		shout("================================");
		say("please pick one ... i'll ask you for input params once you choose something");
		say(">> ");
		String resourceId = in.nextLine();
		say("Excellent! Here are the details of this resource");
		shout("==========================================");
		Resource r = provider.getResource(resourceId);
		if (r.description!=null){
			shout("\t"+r.description);
			shout("--------------------------------------------");
		}
		shout("\tPath: "+r.path);
		if (r.postParams!=null){
		for (String param : r.postParams) {
			shout("\t- PARAM: "+param);
		}
		}
		shout("==========================================");
		say("Please create a JSON string that has ALL the params from the PATH (stuff with a leading colon :) and the post params");
		say("Every parameter is required");
		say(">> ");
		String inputJson = in.nextLine();
		service.execute(resourceId, new JSONObject(inputJson));
		
		
		
		
		
		//Now, lets rip it
//		Provider twitter = oauth.getProvider("facebook");
//		String json = "{" +
//					"\"profile_id\":\"ashisharya\"," +
//					"\"message\":\"eats a lot of food\"" +	
//				"}";
//		JSONObject input = new JSONObject(json);
//		
//		
//		String url = twitter.getResourceAsUrl("create_status_update",input);
//		System.out.println("Here's my URL dude: "+url);
		
		
	}
	
	
	
	
	
}
