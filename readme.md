# Moofwd oAuth Flow

* Use providers.yaml to add oauth provider details
* Test the provider using run script (run.sh) - tested on mac only.

## The run script will:

* Ask you to provide your api key, api secret & callback url
* Will engage with the provider to get the request token (oauth 1.0a)
* Generate the authorization url based on the tokens and show that to you
* __you need to copy this url and paste it in your browser's address bar__ this will start the oauth dance
* Once you've authorized the app, the browser will redirect to the callback url (make sure that url is not redirecting further)
* Copy the callback url (along with query params) from the browser's address bar and paste it back onto the prompt
* The library will now engage with the provider to get your access token

---

* You can now call a resource on the provider (only v1 GET is working as of now, rest of the impl is in progress)
* The library will show you available resources.
* Enter a resource name as it appears in the list on the prompt
* The library will show you necessary params for the resource
* Enter the params as a json string (even if there are no params ... enter {})


## That's it ... you should now see the response from the provider