# Lambda Authentication Proxy

This nodejs library provides a simple authentication proxy for AWS Cloudfront distributions using Lambda@Edge.

## Basic Setup

A typical setup is to use an AWS Lambda handler triggered by a CloudFront Distribution behavior.

### Lambda Handler

The Lambda handler extracts the request, runs it through the desired proxy and either returns a response that triggers the authentication process, or passes the request through to the original destination if the user is authenticated.

A basic template for the lambda handler looks something like [this example](./example/handler.ts).

## Configuration

The proxy is configured by passing in two arguments:

1. The `openid-client` Client you wish to use. This proxy has only been tested with the Github client, although other providers may work as well.
2. The configuration options for the proxy:
  * **REQUIRED** `hashKey`: A unique string used for generating a hash.
  * `baseUrl`: The base url for the site that requires authentication
    * Default: `false` - If not provided the proxy will attempt to determine the base url itself.
  * `authCookieName`: The name of the cookie used to indicate that the user is authenticated.
    * Default: `_auth`
  * `pathLogin`: The path that an unauthenticated user is redirected to that initiates authentication for logged out users.
    * Default: `/auth/login`
  * `pathCallback`: The callback path that Oauth2 authentication is performed at.
    * Default: `/auth/callback`
  * `pathLogout`: The path a user can visit to log out
    * Default: `/auth/logout`
  * `logger`: An object used for logging.
    * Default: `console`

### CloudFront Distribution behavior

The Lambda above gets triggered by an AWS CloudFront distribution behavior.

* Create a CloudFront distribution that traffic to your site or application passes through.
* In the `Lambda Function Associations` section at the bottom of the page add a new CloudFront Event that triggers the lambda on the `Viewer Request` event.
* Add the Lambda ARN identifier. This can be found in the top right corner of the Lambda function. You can not use the `$LATEST` version alias, so you must use a published version of the Lambda function as a part of the identifier.


#### Special Cloudfront Distribution Configuration

This proxy requires two additional options to be specified in the distribution:
* Allowed HTTP Methods: **MUST** be set to `GET, HEAD, OPTIONS, PUT, POST, PATCH, DELETE`, because the form submits a post request
* The Lambda behavior **MUST** have the `include body` option checked, because information is passed in the POST request body.
