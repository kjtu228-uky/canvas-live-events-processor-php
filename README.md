# **Canvas Live Events Processor for PHP**

This script is a JWT-Secured webhook receiver (RSA / RS256 via JWKS) and event processor. It validates the event, responds to Canvas as quickly as possible, then checks for a configured event handler.

An event can have multiple handlers configured. This allows handlers to be kept simple and focused.

## Requirements

No external libraries are required.

All testing was done under PHP 8.2.

Caching and logging is done to local files. This may not be appropriate for all instances, but things have been kept intentionally simple for people to adapt to their own environment.

## Configuration and Setup

Copy the files to your web server and copy config-dist.php to config.php. You can try accessing index.php for the first test, though it should simply respond with an error “Method Not Allowed” (JSON).

### Canvas Developer Key Configuration

As a Canvas Admin, navigate to Admin > Developer Keys. Create a new API Key.

Enter a Key Name and the Redirect URI <path_to_your_instance>/auth.php. You should enable Enforce Scopes and select any scopes needed by your event handlers. Once created, you will need the Client ID and Secret.

### config.php

Many of the default configuration values will work, but the following ones need to be set for your specific instance.

| Constant        | Description                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|-----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| JWKS_URL        | The value for your Canvas instance can be retrieved from [Instructure’s Setup page ](https://developerdocs.instructure.com/services/canvas/data-services/live-events/overview/file.data_service_setup)in the HTTPS section under Delivery Method. At the time of this writing, the needed URL is linked in the sentence “Beta and Production JWKs can be found <here>.” Right-click the “here” link and copy the address to paste into this value. |
| ALLOWED_ISSUERS | The default values here should actually work. In my testing, the events typically use <https://live-events.canvas.instructure.com> as the issuer for JWKS signing.                                                                                                                                                                                                                                                                                 |
| CANVAS_URL      | This is the URL to your Canvas instance.                                                                                                                                                                                                                                                                                                                                                                                                           |
| CLIENT_ID       | This is the client ID created in the above step.                                                                                                                                                                                                                                                                                                                                                                                                   |
| CLIENT_SECRET   | This is the client secret created in the above step.                                                                                                                                                                                                                                                                                                                                                                                               |
| REDIRECT_URI    | This is the value entered in the Redirect URI value in the above step.                                                                                                                                                                                                                                                                                                                                                                             |
| OAUTH_SECRET    | This is a 32-character encryption key used to encrypt the generated authentication token. **Note:** If DEBUG_MODE is set to true, the authentication token will not be encrypted in the local file. If you want the token to be encrypted even in DEBUG_MODE, modify the OAuthService.php file and remove the !DEBUG_MODE check when saving the token.                                                                                             |
| EVENT_HANDLERS  | This is an array defining which event handlers should be used for which events. A key in the array represents the event type posted from Canvas. The value for the key is an array of class names for the corresponding event handlers. This allows for multiple handlers for a single event.                                                                                                                                                      |
| SCOPES          | This is an array of scopes required. Note that you cannot simply add scopes here when you need a new endpoint. You must first make sure the scopes have been added to the Developer Key in Canvas. After you have added new scopes to the Developer Key and to the config.php file, you will need to re-authenticate the application (more details on this process below).                                                                         |

### Authenticating the App

Once the Developer Key is created and the config.php file has been edited correctly, you will need to authorize the app to retrieve the token. Navigate to your REDIRECT_URI to complete the authorization. If successful, you should simply see that the token was generated and saved.

## Canvas Data Services and Live Events

At this point, you are ready to configure Live Events. Please refer to [How do I install Canvas Data Services using Live Events in my account?](https://community.instructure.com/en/kb/articles/661439-how-do-i-install-canvas-data-services-using-live-events-in-my-account) for instructions. Follow the directions to **Configure HTTPS Data Stream** and make sure **Sign Payload** is checked. The URL for the HTTPS Data Stream should be <path_to_your_instance>/index.php.

## Protecting Files

You should configure your web server to deny access to all non-PHP files, or at least all json files. Even with an encrypted token, you don’t want it to be directly accessible. If you want to make sure things are configured properly before authenticating the app, create a file named oauth_token.json in the root folder of the app and try to access it directly.
